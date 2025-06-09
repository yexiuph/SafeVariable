# SafeVar

**SafeVar** is a C++14 library for secure variable storage, memory obfuscation, and anti-cheat protection. It provides a `SafeVar<T>` template for securely storing variables in memory, using ChaCha20 encryption, custom memory pools, and fake address simulation to resist memory scanning and tampering.

## Features

- **Secure Variable Storage:** Obfuscates and encrypts variable values in memory.
- **ChaCha20 Encryption:** Fast, modern stream cipher for data protection.
- **Custom Memory Pool:** Efficient and secure memory management.
- **Fake Address Simulation:** Returns fake addresses to mislead memory scanners.
- **Serialization/Deserialization:** Securely save and restore variable state.
- **Thread-Safe Allocators:** Safe for use in multithreaded environments.
- **Windows Support:** Uses Windows API for real memory allocation.

## Getting Started

### Prerequisites

- Windows (uses `VirtualAlloc`/`VirtualFree`)
- C++14 compatible compiler (Visual Studio 2015+ recommended)

### Usage

1. **Include the header:**

    ```cpp
    #include "SafeVar.hpp"
    ```

2. **Declare and use a secure variable:**

    ```cpp
    SafeVar<int> myScore(1234);

    // Access value
    int score = myScore.Get();

    // Set value
    myScore = 5678;

    // Arithmetic
    myScore += 100;
    ```

3. **Serialization:**

    ```cpp
    auto serialized = myScore.Serialize();
    // ... save to file or send over network
    ```

4. **Deserialization:**

    ```cpp
    SafeVar<int> loadedScore;
    loadedScore.Deserialize(serialized.data(), serialized.size());
    ```

## Security Notes

- **Obfuscation:** Values are encrypted in memory and re-keyed on each write.
- **Fake Addresses:** `GetFakeAddress()` returns a simulated address to mislead cheaters.
- **Memory Validation:** Internal checks ensure memory integrity.

## Example

```cpp
#include "SafeVar.hpp" 
#include <iostream>
int main() {
    SafeVar<int> secret(42); 
    stdcout << "Secret: " << secret << stdendl; 
    secret += 8; stdcout << "Updated: " << secret.Get() << stdendl; stdcout << "Fake address: 0x" << stdhex << secret.GetFakeAddress() << std::endl; 
}
```

## License

Copyright (c) 2025 YXGames.  
All rights reserved.

## Author

Christian Louis Abrigo (YeXiuPH)

---

*For research, anti-cheat, and educational use only. Not intended for malicious purposes.*
