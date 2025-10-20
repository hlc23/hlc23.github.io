
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  puts("=== Mauryan Royal Archive v1.0 ===");
  scribe_function();
  return 0;
}

void scribe_function()
{
  char buffer[264]; // [esp+0h] [ebp-108h] BYREF

  puts("Welcome to the Mauryan Imperial Authentication System");
  printf("Enter the royal inscription: ");
  fflush(stdout);
  if ( !fgets(buffer, 256, stdin) )
  {
    puts("Error reading inscription");
    exit(1);
  }
  buffer[strcspn(buffer, "\n")] = 0;
  printf("Processing inscription: ");
  printf(buffer);
  putchar(10);
  puts("Verifying imperial authority...");
  imperial_access();
}

void imperial_access()
{
  int *v0; // eax
  char flag[256]; // [esp+Ch] [ebp-10Ch] BYREF
  FILE *flag_file; // [esp+10Ch] [ebp-Ch]

  if ( mauryan_empire == 321 && ashoka_edict > 14714 )
  {
    puts("Glory to the Mauryan Empire! Access granted to the royal archives!");
    puts("Royal Inscription: ");
    flag_file = fopen("flag.txt", "r");
    if ( !flag_file )
    {
      v0 = __errno_location();
      printf("Error: Failed to open flag.txt (errno: %d)\n", *v0);
      exit(1);
    }
    if ( !fgets(flag, 256, flag_file) )
    {
      puts("Error: Failed to read from flag.txt");
      fclose(flag_file);
      exit(1);
    }
    printf("Flag: %s", flag);
    fclose(flag_file);
    exit(0);
  }
  puts("Access denied.");
}