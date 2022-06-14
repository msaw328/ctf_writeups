
undefined8 main(void)

{
  int input_op;
  uint input_x;
  uint local_2c;
  
  while( true ) {
    show_menu();
    input_op = read_int("Operator: ");
    if (input_op == 0) break;
    input_x = read_int("x = ");
    (*(code *)ope[input_op + -1])((ulong)input_x,&local_2c);
    __printf_chk(1,"f(x) = %d\n",(ulong)local_2c);
  }
  return 0;
}
