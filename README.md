# macOSFairFree

A python script that patches SINF data in iOS apps downloaded from a tool like ipatool to allow running on macOS.

## Usage

Install [uv](https://docs.astral.sh/uv/), then run:

```sh
uv sync

uv run macosfairfree -i /path/to/input.ipa -c /path/to/credential.bin # without output it's written to /path/to/input-macos.ipa

uv run macosfairfree --input /path/to/input.ipa --output /path/to/output.ipa --credential /path/to/credential.bin
```

## Other Notes

- To retrieve a credential, follow the guide here: [FairPlay Decrypt Credential Retrieval.](https://github.com/EthanArbuckle/fairplay-decrypt/blob/main/credential-retrieval/README.md) Should output a 16-byte credential.bin which you pass with this tool. This requires a jailbroken device.
- IPAs downloaded with Family Sharing don't work (for example if someone else in your family purchased an app and you try to download it, your credential won't be able to decrypt it)
- Some apps will still refuse to launch/won't work on macOS for other reasons. For example, Netflix detects macOS and aborts, Disney Plus gets stuck on loading screen, etc.

## Prior work

- Original [FairFree](https://github.com/roothide/FairFree) (required specifically a device on iOS 14)
- [fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt) for credential retrieval
