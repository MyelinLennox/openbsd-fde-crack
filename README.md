# openbsd-fde-extract

Extracts OpenBSD softraid CRYPTO metadata from an authorized raw disk image
and emits a line accepted by Hashcat 8.0.0 mode 38800.

## Build

```text
go build -o openbsd-fde-extract .
```

## Usage

```text
openbsd-fde-extract -i disk.img
openbsd-fde-extract -i disk.img -o openbsd.hash

# Validate a raw key file, including junk/padding around the 32-byte key
openbsd-fde-extract -i disk.img -k keyfile.bin
```

The output is:

```text
$openbsd-softraid$<pbkdf2-rounds>$<salt-hex>$<encrypted-key-hex>$<check-hex>$1
```

The fields are hexadecimal except for the PBKDF2 round count. The tool reads
only the metadata region and does not modify the image or try passwords.

Use the output with Hashcat 8.0.0 or newer:

```text
hashcat -m 38800 openbsd.hash wordlist.txt
```

Mode 38800 performs PBKDF2-HMAC-SHA1, AES-256-ECB key unmasking, and the
HMAC-SHA1 check. Hashcat mode 38810 is used for OpenBSD volumes using
bcrypt-pbkdf; this extractor currently emits PBKDF2 records only.

The `-k` mode reads the image metadata, then tests every possible 32-byte
window in the supplied raw key file. It reports the byte offset of the first
candidate that decrypts the volume key and passes the HMAC check. It does not
modify either input file.

Use only with disk images you own or are explicitly authorized to examine.
