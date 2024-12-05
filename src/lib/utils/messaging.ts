async function generateKeyPair(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);

  return {
    privateKey: Buffer.from(privateKey).toString("base64"),
    publicKey: Buffer.from(publicKey).toString("base64"),
  };
}

async function encryptMessage(
  publicKey: string,
  message: string
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);

  const importedPublicKey = await crypto.subtle.importKey(
    "spki",
    Buffer.from(publicKey, "base64"),
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"]
  );

  const encrypted = await crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    importedPublicKey,
    data
  );

  return Buffer.from(encrypted).toString("base64");
}

async function decryptMessage(
  privateKey: string,
  encryptedMessage: string
): Promise<string> {
  const decoder = new TextDecoder();
  const data = Buffer.from(encryptedMessage, "base64");

  const importedPrivateKey = await crypto.subtle.importKey(
    "pkcs8",
    Buffer.from(privateKey, "base64"),
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    importedPrivateKey,
    data
  );

  return decoder.decode(decrypted);
}

export { decryptMessage, encryptMessage, generateKeyPair };
