# Operation Dawn: The Reconnaissance Plate

**Category:** Misc

## Solution

### 1. Inspect the image bits

I checked `recon-plate (1).png`, a 256 × 256 RGB image. The visible image had no readable annotation, and I found no obvious appended payload, so I inspected its RGB bit planes.

I read pixels in row-major RGB order. For each plane, I packed the selected bits into bytes. Both planes 0 and 1 began with a four-byte big-endian length followed by GZIP magic `1f 8b`.

### 2. Read both hidden archives

Each GZIP payload decompressed into a TAR containing `plate/annotation.txt`, `plate/caption.txt`, and `plate/grid.txt`. This extractor uses Pillow and NumPy and reads those members directly:

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
        for name in ('plate/annotation.txt', 'plate/caption.txt', 'plate/grid.txt'):
            print(plane, name, archive.extractfile(name).read().decode().strip())
```

### 3. Use the captions to distinguish the records

Plane 0's annotation was:

```text
DRILL SERIAL 11 HOLD THE RIDGE LINE UNTIL RELIEVED CODE 48B473
```

Its caption said `Range card practice plate. Not for action. Plate 2 of 9.` I therefore rejected `48B473` as the practice code.

Plane 1 contained:

```text
RECON SERIAL 11 THE GUNS BEHIND THE RIDGE CODE 3F8C21
```

The caption was `North ridge, 0500. Low cloud over the valley. Plate 7 of 9.` Its grid read `grid 41-D  elev 540  bearing 075  range 1200`, supporting the reconnaissance record.

### 4. Format the annotation as the flag

I took serial `11`, converted `THE GUNS BEHIND THE RIDGE` to lowercase snake_case, and appended code `3f8c21`:

```text
11_the_guns_behind_the_ridge_3f8c21
```

I then added the required flag wrapper.

## Flag

```text
CSCTF{11_the_guns_behind_the_ridge_3f8c21}
```
