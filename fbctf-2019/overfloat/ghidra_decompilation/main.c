undefined8 main(void)

{
  float user_input [12];
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  alarm(0x1e);
  __sysv_signal(0xe,timeout);
  puts(
      "                                 _ .--.        \n                                ( `    )      \n                             .-\'      `--,     \n                  _..----.. (            )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(       (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _| _|  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_| _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_     ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                   ;____;                     \n                     \\YT/                     \n                     ||                       \n                     |\"\"|                    \n                    \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?"
      );
  memset(user_input,0,0x28);
  chart_course(user_input);
  puts("BON VOYAGE!");
  return 0;
}
