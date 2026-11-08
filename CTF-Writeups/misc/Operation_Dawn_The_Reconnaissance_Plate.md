# Operation Dawn: The Reconnaissance Plate

**Category:** Misc

## Solution

1. I checked `recon-plate (1).png`, a 256 × 256 RGB image. I found no readable annotation or obvious appended data, so I examined the RGB bit planes.
2. I extracted planes 0 and 1 in row-major RGB order and packed the bits into bytes. Each stream began with a four-byte big-endian length, followed by GZIP data containing a TAR archive. The extraction logic below prints the annotation and caption directly and needs Pillow and NumPy:

   ```python
   import gzip
   import io
   import struct
   import tarfile
   import numpy as np
   from PIL import Image

   pixels = np.asarray(Image.open('recon-plate (1).png').convert('RGB'))
   for plane in (0, 1):
       payload = np.packbits((pixels >> plane) & 1).tobytes()
       length = struct.unpack('>I', payload[:4])[0]
       assert payload[4:6] == b'\x1f\x8b'
       data = gzip.decompress(payload[4:4 + length])
       with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
           for name in ('plate/annotation.txt', 'plate/caption.txt'):
               print(plane, name, archive.extractfile(name).read().decode().strip())
   ```

3. Plane 0's caption called it a practice plate, so I rejected its code `48B473`. Plane 1 contained the real annotation:

   ```text
   RECON SERIAL 11 THE GUNS BEHIND THE RIDGE CODE 3F8C21
   ```

4. I combined serial `11`, the message in lowercase snake_case, and code `3f8c21`, then wrapped the result in the flag format.

## Flag

```text
CSCTF{11_the_guns_behind_the_ridge_3f8c21}
```

> **Note:** The image is absent, so I could not rerun the extractor. I preserved the recorded payloads and flag from my detailed solution.
