void chart_course(float *external_buffer)

{
  int reading_done;
  uint lat_i;
  uint lon_i;
  float float_value_from_buffer;
  char internal_buffer [104];
  uint index;
  
  index = 0;
  do {
    if ((index & 1) == 0) {
      lat_i = ((int)(index + (index >> 0x1f)) >> 1) % 10;
      printf("LAT[%d]: ",(ulong)lat_i,(ulong)lat_i);
    }
    else {
      lon_i = ((int)(index + (index >> 0x1f)) >> 1) % 10;
      printf("LON[%d]: ",(ulong)lon_i,(ulong)lon_i,(ulong)lon_i);
    }
    fgets(internal_buffer,100,stdin);
    reading_done = strncmp(internal_buffer,"done",4);
    if (reading_done == 0) {
      if ((index & 1) == 0) {
        return;
      }
      puts("WHERES THE LONGITUDE?");
      index = index - 1;
    }
    else {
      _float_value_from_buffer = atof(internal_buffer);
      memset(internal_buffer,0,100);
      external_buffer[(long)(int)index] = (float)_float_value_from_buffer;
    }
    index = index + 1;
  } while( true );
}
