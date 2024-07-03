---
title: GoogleCTF quals 2024 encrypted runner
categories:
- ctf
- pwn
- crypto
---

This challenge is really cool, which I did not actually solve during this year's GoogleCTF. Furthermore, this is my first participation for international CTF events and I enjoyed a lot ("struggling all the way through" lol). Due to the official write-up that has been published after the contest finished, this post merely adds more detail and demonstrates how I tried to approach ("fail") towards a solution.


## Confusion and blockers

This section mainly illustrates how I attempted to approach this challenge and why I was blocked during the contest. The attachment consists of a Python file and a binary about AES encryption/decryption. 

At the beginning, I started looking at the Python file, which basically resolves user input, encrypts valid user input, and exchanges the encrypted form
of a command with users back and forth. Moreover, there are only three commands, such as ls and echo, available in the whitelist, while other commands excluded in the list will not be allowed to execute. It seemed like that the application logic in Python layer had been non-vulnerable so far. 

Secondly, I had the AES binary left for inspection. I loaded it into Ghidra for reverse engineering. I was assuming that there were any overflow vulnerabilities available, such that I could get a shell after exploitation. However, inputs from Python layber are controlled in length as the following code snippet shown. In this case, only 16 bytes are sent to the AES binary for further cryptographic operations.
```python
def helper(cmd, data):
  if cmd == "encrypt":
    data = [ord(c) for c in data]
  else:
    data = list(bytes.fromhex(data))

  while len(data) < 16:
    data.append(0)

  # 16 bytes should be enough for everybody...
  inp = cmd + " " + " ".join("%02x" % c for c in data[:16])
  res = subprocess.check_output("./aes", input = inp.encode())
  return bytes.fromhex(res.decode())
```

Looking at the code snippet dealing with these inputs:
```c
      __isoc99_scanf("%s",cmd);
      for (idx = 0; idx < 0x10; idx = idx + 1) {
        __isoc99_scanf("%x",plaintext + idx);
      }
      AES_init_ctx(aes_ctx,&aes_key);
```

It is clear that the binary only takes a string and 16 hex bytes, which could be have been a game killer, I did not figure out at that moment though. Hence, it looked fine to me. So, I had a rough conclusion there is no overflow vulnerabulity available such as stack overflow. In the other words, we cannot get a shell somehow as a typical pwn challenge. In turn, what blew in mind was only to get AES key, then encrypt `ls 'cat /flag'` to get the flag. However, I spent quite a few hours on brainstorming how to access the AES key by available commands. 

### The closest approach

In fact, there was even a moment when I was sort of close to but missed out on the most important clue, which points to what inputs could be taken by Python code as the preceeding code snippet. It could be seen in a way that we could type in whatever we want and this may give us more sense of how these messy inputs could be processed internally. However, the leverage becomes more clear when we look at somewhere in the AES binary, which I explain in later sections.

```python
line = input()
# ...
what, rest = line.split(" ", 1)
# command checking against whitelist
res = helper("encrypt", rest)
```

## Make weird things happened
### Direction 1: try all possible inputs

Referring to another [write-up post](https://medium.com/@harryfyx/googlectf-quals-2024-encrypted-runner-30c277765154), I tried these two inputs locally:
```
encrypt ls ȅȅȅȅȅȅȅȅȅȅȅȅȅ
Encrypted command: a75d08c42ca08d8151c5485855c4ed13

encrypt ls ȃȃȃȃȃȃȃȃȃȃȃȃȃ
Encrypted command: a75d08c42ca08d8151c5485855c4ed13
```

It is interesting that two different commands derive the same encrypted data, meaning that something epsecially AES parts does not handle properly.

### Direction 2: a direct instinct to check any cryptographic implementation

If one has a strong intuition, may check if the current AES is implemented correctly, such as data type, length of data? Hence, the second clue shows up as the following:
```c
undefined8 main(void){
    uint plaintext [16];
    // unnecessary ...
    for (idx = 0; idx < 0x10; idx = idx + 1) {
        __isoc99_scanf("%x",plaintext + idx);
    }
}
```

Notably, the type of plaintext is unsigned input rather than char or byte. This maybe a possible root cause of same encrypted data for two different commands as mentioned previously. Hence, its implementation differs from the standard library, and I explain with the openssl library:
```c

# this challenge
void AES_ECB_encrypt(undefined8 aes_ctx,uint *plaintxt)

# openssl
AES_ecb_encrypt (const unsigned char *in, unsigned char *out, const AES_KEY *key, const int enc)

```

We could input UTF-8 characters in Python, which could also be processed by the AES binary. That is to say that the binary potentially takes more than one byte.

## Debugging is always good

Whenver dealing with pwn challenges, debugging is the best way to figure how a program takes an input. Similary, referring to the debug script from [same post](https://medium.com/@harryfyx/googlectf-quals-2024-encrypted-runner-30c277765154) again, I ran it and got a list of intermediate data generated during AES encryption, feeding the AES binary with `encrypt 6c 73 20 100 100 100 100 100 100 100 100 100 100 100 100 100`:

```
('AddRoundKey', [108, 115, 32, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256])                          

('SubBytes', [93, 65, 19, 308, 305, 306, 307, 308, 305, 306, 307, 308, 305, 306, 307, 308])                               

('ShiftRows', [76, 131, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])                                                      
                                
('MixColumns', [76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 125, 0, 0, 131, 0, 0])
```

If one has learned the internals of AES encryption, may feel the weird thing happening after SubBytes, which uses input byte to index a row/col in the s-box table to retrieve the substituted value. Here, except the first three bytes, all others are 0. Looking back, their indexes to the s-box go over its boundary, e.g., `308, 305, 306, 307, 308, 305, 306, 307, 308, 305, 306, 307, 308` since s-box only cover 16*16, which is 256 as maximum. 



## back to pwn methodology

I still felt confused even I noticed a lot of zeros shown above. What does it mean? What is it doing with printing a flag? 

In a traditional manner, while dealing with pwn challenges, especially heap topics, we usually need to leak the address of a loaded libc or heap then overwrite the value of a hook function or something else so as to get a shell. The same methodology should have been adapted in this challenge. Hence, we could educatively guess that those zeros might help leak the AES key.

### Leaking the AES key

People may think of what if this zeros-after-substitute situation happens in a correct implementation? What does it mean if this occurs? Cool, you are getting close to a solution. Having these zeros in a normal implementation actually reflects the values after the first round of `AddRoundKey`. They are 0x52, which in turn points to the substituted value in s-box[0x52], and it is 0x0.
This is to say, from encryption perspective, we now have a formula - `data ^ key == 0x52`, which means that data xor key equals 0x52. If we mathmatically move the data to the right side, it becomes `key == 0x52 ^ data`, and thus we could be able to leak the AES key in case of having original data. For example, we reuse the previous case:
```
encrypt ls ȅȅȅȅȅȅȅȅȅȅȅȅȅ
Encrypted command: a75d08c42ca08d8151c5485855c4ed13
run a75d08c42ca08d8151c5485855c4ed13
Output: ls: cannot access ''$'\017''['$'\034\203'':Q'$'\031''z'$'\a\035\252\370\373': No such file or directory
```

Is the original data `ȅȅȅȅȅȅȅȅȅȅȅȅȅ` here? No, it could be seen in a way that decrypted data here is not the same because of misimplementation. Instead, the content right after `cannot access` is the original data. Hence, we could make use of this information to leak the AES key according to the previous formula. 
Here, I refer to the official solution released by Google team:
```Python
# we do not know the first three bytes because they are not zeros during SubByte stage of AES encryption.
key = [0, 0, 0] + [0x52 ^ o for o in out]
for first in range(256):
  if found: break
  key[0] = first
  for second in range(256):
    if found: break
    key[1] = second
    for third in range(256):
      key[2] = third
      cipher = AES.new(bytes(key), AES.MODE_ECB)
      # encrypted_echo is the encrypted example command shown when interacting with the server.
      pt = cipher.decrypt(encrypted_echo)
      if pt.startswith(b'echo'):
        print("plaintext", pt)
        found = True
        break
```

### Craft a command to print flag

Once we have the AES key, capturing the flag is way easier by crafting a command like `ls 'cat /flag'` and encrypting it using this key. Finally, we send the encrypted data to the server, and it will print the flag soon.

```python
cipher = AES.new(bytes(key), AES.MODE_ECB)
pt = cipher.encrypt(b"ls 'cat /flag'")
```

## Takeway

Writing a write-up is not actually my incentive, and sort of boring especially when one knows the solution already. What I want to demonstrate in this post is why I got blocked, and is to help me build a good mind mobility to play CTF for future. Anyway, I list up what I have learned throughout the entire journey:
 - Carefully look at the input flow for each layer, e.g., from Python to C. For the topmost layer that takes user inputs first, understand how it processes data.
 - Brainstorm what type of input this program could take on?
 - Whenever cryptographic library is involved, one needs to check and validate if its implementation is correct compared to the official one.
 - Follow pwn methodology: leak something and break something exceptionally.
 - Finally, happy hacking is always good for mental health, even though one cannot solve during the contest.




