
undefined8 main(void)

{
  int iVar1;
  time_t time2;
  byte bVar2;
  char cVar3;
  long in_FS_OFFSET;
  int final_check_gt_5e4cf66f;
  int counter_0x18;
  int counter_from_0_to_100;
  uint local_158;
  uint local_154;
  size_t buffer_length;
  byte *flagbuffer;
  double local_140;
  time_t start_time;
  undefined *local_130;
  undefined *local_128;
  undefined *local_120;
  undefined *local_118;
  long time_diff;
  undefined8 local_108;
  undefined2 local_100;
  undefined8 local_fe;
  undefined2 local_f6;
  undefined8 local_f4;
  undefined2 local_ec;
  undefined8 local_ea;
  undefined2 local_e2;
  undefined8 local_e0;
  undefined2 local_d8;
  undefined8 local_d6;
  undefined2 local_ce;
  undefined8 local_cc;
  undefined2 local_c4;
  undefined8 local_c2;
  undefined2 local_ba;
  undefined8 local_b8;
  undefined2 local_b0;
  undefined8 local_ae;
  undefined2 local_a6;
  char buff_weird [10];
  byte buffer_32 [32];
  undefined buffer_100 [100];
  undefined local_14;
  long stack_chk_var;
  
  stack_chk_var = *(long *)(in_FS_OFFSET + 0x28);
  buffer_length = 0x29;
  final_check_gt_5e4cf66f = 0;
  counter_from_0_to_100 = 0;
  while (counter_from_0_to_100 < 100) {
    buffer_100[counter_from_0_to_100] = 0x20;
    counter_from_0_to_100 = counter_from_0_to_100 + 1;
  }
  local_14 = 0;
  local_108 = 0x8ba0e2;
  local_100 = 0;
  local_fe = 0x99a0e2;
  local_f6 = 0;
  local_f4 = 0xb9a0e2;
  local_ec = 0;
  local_ea = 0xb8a0e2;
  local_e2 = 0;
  local_e0 = 0xbca0e2;
  local_d8 = 0;
  local_d6 = 0xb4a0e2;
  local_ce = 0;
  local_cc = 0xa6a0e2;
  local_c4 = 0;
  local_c2 = 0xa7a0e2;
  local_ba = 0;
  local_b8 = 0x87a0e2;
  local_b0 = 0;
  local_ae = 0x8fa0e2;
  local_a6 = 0;
  flagbuffer = (byte *)malloc(0x29);
  getline((char **)&flagbuffer,&buffer_length,stdin);
  buffer_32[0] = 0x70;
  buffer_32[1] = 0x77;
  buffer_32[2] = 0x6e;
  buffer_32[3] = 0x34;
  buffer_32[4] = 0x77;
  buffer_32[5] = 0x6c;
  buffer_32[6] = 0x69;
  buffer_32[7] = 0x6b;
  buffer_32[8] = 0x37;
  buffer_32[9] = 0x5f;
  buffer_32[10] = 0x65;
  buffer_32[11] = 0x77;
  buffer_32[12] = 0x76;
  buffer_32[13] = 0x68;
  buffer_32[14] = 0x6e;
  buffer_32[15] = 0x33;
  buffer_32[16] = 0x75;
  buffer_32[17] = 0x6e;
  buffer_32[18] = 0x62;
  buffer_32[19] = 0x5f;
  buffer_32[20] = 0x37;
  buffer_32[21] = 0x31;
  buffer_32[22] = 0x30;
  buffer_32[23] = 0x74;
  counter_0x18 = 0;
  while (counter_0x18 < 0x18) {
    if ((buffer_32[counter_0x18] == flagbuffer[(long)final_check_gt_5e4cf66f + 9]) &&
       ((counter_0x18 - (counter_0x18 >> 0x1f) & 1U) + (counter_0x18 >> 0x1f) == 1)) {
      final_check_gt_5e4cf66f = final_check_gt_5e4cf66f + 1;
    }
    counter_0x18 = counter_0x18 + 1;
  }
  if (buffer_length != 0x29) {
    final_check_gt_5e4cf66f = 1;
  }
  if ((final_check_gt_5e4cf66f + 4U & 0xf) == 0) {
    puts("Wait 20 min please.\nMake your terminal wider to see progress bar.");
    start_time = time((time_t *)0x0);
    counter_0x18 = 0;
    while (counter_0x18 < 0x192643) {
      if (counter_0x18 % 100 == 0) {
        counter_from_0_to_100 = 0;
        while (counter_from_0_to_100 < counter_0x18 / 0x4062) {
          buffer_100[counter_from_0_to_100] = 0x3d;
          counter_from_0_to_100 = counter_from_0_to_100 + 1;
        }
        buffer_100[counter_from_0_to_100] = 0x3e;
        time2 = time((time_t *)0x0);
        time_diff = time2 - start_time;
        local_140 = 0.00000000;
        if ((time_diff != 0) && (counter_0x18 != 0)) {
          local_140 = ((1648195.00000000 - (double)counter_0x18) * (double)time_diff) /
                      (double)counter_0x18;
        }
        local_154 = (int)local_140 / 0x3c;
        local_158 = (int)local_140 % 0x3c;
        printf((char *)(double)((float)counter_0x18 / 16482.00000000),"\r%s [%s] %.2f%% ETA %d:%d",
               (undefined8 *)((long)&local_108 + (long)((counter_0x18 / 100) % 10) * 10),buffer_100,
               (ulong)local_154,(ulong)local_158);
        fflush(stdout);
      }
      usleep(1000);
      *(ulong *)(flagbuffer + 0x15) = *(ulong *)(flagbuffer + 0x15) ^ 0x45a9278d6f0be1c3;
      final_check_gt_5e4cf66f = final_check_gt_5e4cf66f * 2;
      counter_0x18 = counter_0x18 + 1;
    }
    final_check_gt_5e4cf66f = 1;
    puts("");
    buff_weird[9] = ')';
    buff_weird[0] = '_';
    buff_weird[8] = ';';
    buff_weird[1] = 't';
    buff_weird[7] = 'k';
    flagbuffer[buffer_length - 2] = 0;
    if (((((((flagbuffer[1] ^ *flagbuffer) == 0x49) && ((flagbuffer[2] ^ flagbuffer[1]) == 0x45)) &&
          ((flagbuffer[3] ^ flagbuffer[2]) == 0x2a)) &&
         (((flagbuffer[4] ^ flagbuffer[3]) == 0x28 && ((flagbuffer[5] ^ flagbuffer[4]) == 0x46))))
        && (((flagbuffer[6] ^ flagbuffer[5]) == 0x5d &&
            (((flagbuffer[7] ^ flagbuffer[6]) == 0x10 && ((flagbuffer[8] ^ flagbuffer[7]) == 0x23)))
            ))) && ((*flagbuffer ^ flagbuffer[8]) == 0x26)) {
      bVar2 = (byte)((char)*flagbuffer >> 7) >> 3;
      if (final_check_gt_5e4cf66f == 1) {
        cVar3 = '\x19';
      }
      else {
        cVar3 = '\x18';
      }
      if (cVar3 == (byte)((*flagbuffer + bVar2 & 0x1f) - bVar2)) {
        buff_weird[2] = '0';
        buff_weird[6] = 'l';
        buff_weird[3] = '_';
        buff_weird[5] = '4';
        buff_weird[4] = 'w';
        iVar1 = strncmp((char *)(flagbuffer + 0x1d),buff_weird,10);
        if (iVar1 == 0) {
          iVar1 = FUN_0010092a(&flagbuffer);
          if (iVar1 != 0x61) {
            bVar2 = (byte)((char)*flagbuffer >> 7) >> 4;
            final_check_gt_5e4cf66f = (int)(char)((*flagbuffer + bVar2 & 0xf) - bVar2) << 8;
          }
          if (*(long *)(flagbuffer + 0x15) == 0x20c44eba3078d09c) {
            *(ulong *)(flagbuffer + 0x15) = *(ulong *)(flagbuffer + 0x15) ^ 0x45a9278d6f0be1c3;
            time((time_t *)&final_check_gt_5e4cf66f);
            if (0x5e4cf66f < final_check_gt_5e4cf66f) {
              puts("");
              local_130 = &FOR;
              local_128 = &GIVE;
              local_120 = &US;
              local_118 = &S_;
              printf("\nCorrect :)\nFLAG:\tSUSEC{%s}\n%s%s%s%s\n",flagbuffer,&FOR,&GIVE,&US,&S_);
              goto LAB_001011de;
            }
          }
        }
      }
    }
  }
  puts("Wrong!\n");
LAB_001011de:
  if (stack_chk_var != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

