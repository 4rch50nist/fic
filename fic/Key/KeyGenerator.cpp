

#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
  if (sodium_init() < 0) {
    std::cerr << "sodium_init failed\n";
    return 1;
  }

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  if (crypto_sign_keypair(pk, sk) != 0) {
    std::cerr << "key generation failed\n";
    return 1;
  }
  {
    std::ofstream pub("public.key", std::ios::binary);
    if (!pub) {
      std::cerr << "failed to open public.key\n";
      return 1;
    }
    if (!pub.write(reinterpret_cast<char *>(pk), sizeof(pk))) {
      std::cerr << "failed to write public key\n";
      return 1;
    }
  }
  {
    int fd =
        open("secret.key", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);

    if (fd < 0) {
      std::cerr << "failed to open secret.key\n";
      return 1;
    }

    ssize_t written = write(fd, sk, sizeof(sk));
    if (written != sizeof(sk)) {
      std::cerr << "failed to write secret key\n";
      close(fd);
      return 1;
    }

    if (fsync(fd) != 0) {
      std::cerr << "warning: fsync failed on secret.key\n";
    }

    close(fd);
  }
  sodium_memzero(sk, sizeof(sk));

  std::cout << "Keys generated securely\n";

  return 0;
}
