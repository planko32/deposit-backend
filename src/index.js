import { createClient } from "@supabase/supabase-js";
import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey } from "@scure/bip32";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import * as secp from "@noble/secp256k1";

function json(res, status = 200) {
  return new Response(JSON.stringify(res), {
    status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type,authorization",
      "access-control-allow-methods": "POST,OPTIONS",
    },
  });
}

function getBearer(req) {
  const h = req.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : null;
}

function deriveEvmAddressFromMnemonic(mnemonic, index) {
  const seed = mnemonicToSeedSync(mnemonic);
  const root = HDKey.fromMasterSeed(seed);
  const child = root.derive(`m/44'/60'/0'/0/${index}`);
  if (!child.privateKey) throw new Error("Failed to derive private key");

  const pub = secp.getPublicKey(child.privateKey, false); // uncompressed 65 bytes
  const hash = keccak_256(pub.slice(1)); // remove 0x04 prefix
  const address = "0x" + bytesToHex(hash.slice(-20));
  return address.toLowerCase();
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: { "access-control-allow-origin": "*" } });

    const url = new URL(req.url);
    if (url.pathname !== "/get-or-create-deposit-address" || req.method !== "POST") {
      return json({ error: "Not found" }, 404);
    }

    const token = getBearer(req);
    if (!token) return json({ error: "Missing Authorization Bearer token" }, 401);

    const supabaseAnon = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, { auth: { persistSession: false } });
    const supabaseAdmin = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });

    // تأكيد المستخدم من توكن Supabase
    const { data: u, error: uErr } = await supabaseAnon.auth.getUser(token);
    if (uErr || !u?.user?.id) return json({ error: "Invalid token" }, 401);
    const userId = u.user.id;

    // إذا عنده عنوان موجود رجّعه
    const { data: existing, error: exErr } = await supabaseAdmin
      .from("deposit_addresses")
      .select("address, derivation_index")
      .eq("user_id", userId)
      .maybeSingle();

    if (exErr) return json({ error: exErr.message }, 500);
    if (existing?.address) return json({ user_id: userId, address: existing.address, index: existing.derivation_index });

    // خذ index جديد
    const { data: idx, error: idxErr } = await supabaseAdmin.rpc("next_deposit_index");
    if (idxErr) return json({ error: idxErr.message }, 500);

    const index = Number(idx);
    const address = deriveEvmAddressFromMnemonic(env.HD_MNEMONIC, index);

    const { error: insErr } = await supabaseAdmin.from("deposit_addresses").insert({
      user_id: userId,
      chain: "bsc",
      token: "USDT",
      address,
      derivation_index: index,
    });
    if (insErr) return json({ error: insErr.message }, 500);

    await supabaseAdmin.from("balances").upsert({ user_id: userId, usdt_balance: 0 });

    return json({ user_id: userId, address, index });
  },
};
