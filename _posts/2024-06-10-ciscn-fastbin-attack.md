---
title: A very typical heap challenge
categories:
- ctf/pwn
- heap
---

This post demonstrates an in-depth analysis of a fairly typical heap challenge - fastbin attack. Even though this is a very first time on analyzing heap challenges, it does not mean that I have to follow common approaches, limiting the use of other novel techiniques. Additionally, I find it more educative to share some patterns of this type of vulnerability, so as to apply those patterns in a next similar challenge. The [attachment]({{ site.baseurl }}/assets/binary/2024-06-10-ciscn-fastbin-attach.md/orange_cat_diary_cffa870fbc6e887360d16817570431a9.zip) consists of an executable and a libc library of the version 2.23. This challenge comes from CISCN 2024.

## Understanding the application logic

Loading this binary rather than libc file into Ghidra, it can be seen that this is a command-line binary, serving the management of a user-created diary. Its main functionality mainly manifests as creation of a new diary, modification, deletion, and display. The decompiled pseudo C code of its main function is shown as following:
 
```c
void main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined name [40];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init();
  puts("Hello, I\'m delighted to meet you. Please tell me your name.");
  memset(name,0,0x20);
  read(0,name,0x1f);
  printf("Sweet %s, please record your daily stories.\n",name);
  do {
    while( true ) {
      while( true ) {
        menu();
        iVar1 = read_choice();
        if (iVar1 != 2) break;
        show_diary();
      }
      if (iVar1 < 3) break;
      if (iVar1 == 3) {
        del_diary();
      }
      else if (iVar1 == 4) {
        edit_diary();
      }
    }
    if (iVar1 == 1) {
      add_diary();
    }
  } while( true );
}
```

Nothing is obviously vulnerable and interesting until I checked the `show_diary` and `del_diary`, two of which only execute once for its correspinding operation, for example, `del_diary` only performs a deletion once all the way out. In the preceeding code snippet, `chance_show` and `num_diary` both are global variables, which are set up as 1 by default.
```c
undefined8 show_diary(void)
{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (0 < chance_show) {
    fwrite(heap_ptr,1,(long)heap_length_content,stdout);
    chance_show = chance_show + -1;
  }
  puts("Diary view successful.");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

undefined8 del_diary(void)
{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (0 < num_diary) {
    free(heap_ptr);
    num_diary = num_diary + -1;
  }
  puts("Diary deletion successful.");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

By diving into remaining two functions, I found that `add_diary` mallocs a block of memory according to user input with a size of 4096 in maximum, while `edit_diary` - most interesting and vulnerable one - allows 8 bytes to overflow. That means users not only have a control over the length of this memory, but have extra 8 bytes to manipulate, which might lead to UAF (use-after-use) vulnerability in case that the freed chunk is still accessible by users.
```c
undefined8 edit_diary(void)

{
  long lVar1;
  uint length_content;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Please input the length of the diary content:");
  length_content = read_choice();
  /* vul is here, allowing 8 more bytes to overflow */
  /* UAF is possible in case of freed chunks controlled by users */
  if (heap_length_content + 8U < length_content) {
    puts("The diary content exceeds the maximum length allowed.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("Please enter the diary content:");
  read(0,heap_ptr,(long)(int)length_content);
  puts("Diary modification successful.");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

## Identifying threat models

Through the initial inspection in the previous section, I identified a few vulnerable points:
* heap overflow
* use-after-use
* information leak

The first two points are relatively observable, while information leak is accomplished by the combination of other two somehow, potentially leaking the crucial information to be leveraged sooner, e.g., base address of libc. The subsection will cover the detail of these vulnerabilities along with introducing essential basics about heap memory management.

### Overflowing allocated memory

Thanks to the aforementioned 8-byte overflow, attackers maybe able to manipulate the content of adjacent chunk if they allocate memory with a proper size. Beware that the first allocated chunk does not calculate the field `prev_size` into the field `size` as its `P` flag is set as 1 by default. This is to say, while allocating a block with 24 bytes, the actual size of this chunk is 0x20, which does not preserve for  `prev_size`. Let us validate that by adding a diary with the size of 24 bytes:
```
Please input your choice:1                                                                                                
Please input the length of the diary content:24                                                                           
Please enter the diary content:                                                                                           
aaaa                                                                                                                      
Diary addition successful.
```

At this moment, enter into interactive mode by sending an interrupt signal (Ctrl + C or equivalent) to GDB. Type the command `heap chunks` to enable heap analysis:
```bash
gef➤  heap chunks 
Chunk(addr=0x5dd9313f3010, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005dd9313f3010     61 61 61 61 0a 00 00 00 00 00 00 00 00 00 00 00    aaaa............]
Chunk(addr=0x5dd9313f3030, size=0x20fe0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
gef➤  x/10xg 0x00005dd9313f3010-0x10
0x5dd9313f3000: 0x0000000000000000      0x0000000000000021
0x5dd9313f3010: 0x0000000a61616161      0x0000000000000000
0x5dd9313f3020: 0x0000000000000000      0x0000000000020fe1
0x5dd9313f3030: 0x0000000000000000      0x0000000000000000
0x5dd9313f3040: 0x0000000000000000      0x0000000000000000
```

As shown above, he size of this chunk is 0x21, setting `P` flag as 1 and indicating the previous chunk being in use. Therefore, the size is actually composed of 8 bytes of `size` field and 24 bytes of the user-requested area. Note that the binary is running on x86-64 machine and thus `size` field occupies 8 bytes.

It is clear that 8-byte overflow on this chunk will cover the value of `size` field of next chunk, which is the top chunk! Now the remaining space of the top chunk is 20fe1. Hackers could modify as 0xfe1, requesting a chunk of size larger than the modified size of the top chunk and forcing heap managament program to service this allocation by extending the current top chunk. Moreover, the old chunk is being freed and the new top chunk is next to the end of the old one. 


### Getting top chunk freed

For convenience, I modified the size of top chunk straightaway without writing a script for this moment. 

```bash
gef➤  set *(0x5dd9313f3020+0x8)=0xfe1
gef➤  x/10xg 0x00005dd9313f3010-0x10
0x5dd9313f3000: 0x0000000000000000      0x0000000000000021
0x5dd9313f3010: 0x0000000a61616161      0x0000000000000000
0x5dd9313f3020: 0x0000000000000000      0x0000000000000fe1
0x5dd9313f3030: 0x0000000000000000      0x0000000000000000
0x5dd9313f3040: 0x0000000000000000      0x0000000000000000
```

Turning to continued execution of the target binary, we need to allocate a new chunk of size larger than 0xfe1, which could be 0x1000, satisfying the validity checking. 

```bash
gef➤  c                                                                                                          [44/1968]
Continuing.                                                                                                               
1                                                                                                                         
Please input the length of the diary content:4096                                                                         
Please enter the diary content:                                                                                           
aaaa                                                                                                                      
Diary addition successful.
```

By checking the current heap bins, I found the freed top chunk has been placed on unsorted bins since the size of the Top chunk, when it is freed, is larger than the fastbin sizes and it got added to list of unsorted bins.
```bash
gef➤  heap bins unsorted 
──────────────────────────────────────── Unsorted Bin for arena at 0x75f79afc4b20 ────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x5dd9313f3020, bk=0x5dd9313f3020
 →   Chunk(addr=0x5dd9313f3030, size=0xfc0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
```

Notably, there are two conditions to be met if we want to have the free old chunk added to unsorted bins:
* Top chunk's size has to be page aligned (the end of top chunk should be page aligned)
* Top chunk's prev_inuse bit has to be set


### Gaining control over fastbin





### Taking over on control flow

### Searching for proper one-gadget
