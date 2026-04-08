function buf2hex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function setup() {
  let openssl = Process.findModuleByName("libcrypto-3-zm.dll");
  while (!openssl) {
    await sleep(10);

    openssl = Process.findModuleByName("libcrypto-3-zm.dll");
  }

  console.log(`found crypto in ${Process.id} at ${openssl}`);

  Interceptor.attach(openssl.getExportByName("CRYPTO_gcm128_init"), {
    onEnter(args) {
      console.log(
        `[${args[0]}] gcm init key: ${buf2hex(args[1].readByteArray(32)!)}`,
      );
    },
  });
}

setup().catch((err) => console.error(err));
