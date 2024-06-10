---
title: A very typical heap challenge
categories:
- ctf/pwn
---

This post demonstrates an in-depth analysis of a fairly typical heap challenge - fastbin attack. Even though this is a very first time on analyzing heap challenges, it does not mean that I have to follow common approaches, limiting the use of other novel techiniques. Additionally, I find it more educative to share some patterns of this type of vulnerability, so as to apply those patterns in a next similar challenge. The [attachment]({{ site.baseurl }}/assets/binary/2024-06-10-ciscn-fastbin-attach.md/orange_cat_diary_cffa870fbc6e887360d16817570431a9.zip) consists of an executable and a libc library of the version 2.23. 

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
Through initial inspection in the previous section, I identified a few vulnerable points:
* heap overflow
* use-after-use
* information leak

The first two points are relatively observable, while information leak is accomplished in the combination of other two somehow.