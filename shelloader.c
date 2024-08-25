/* shelloader.c - Linux 64-Bit mmap based shell code loader
 *-------------------------------------------------------------------------
 * pass it your object file and it will display and execute the shellcode
 * date 3/8/2013
 * updated 8/24/2024
 * author Travis Montoya
 *
 * gcc -o shelloader shelloader.c
 *
 * UPDATES:
 * - Moved to single file, removed Makefile, added options using getopt
 * - Checking that the ELF OBJ is 64 Bit, fixing memory leak
 * - Error checking, variable fixes, usage, check entire e_ident now
 * - Added line breaking for shellcode dump
 * - Added option to execute shellcode or just display shellcode
 * - Added more verbose output for user
 * - Added null byte warning
 *------------------------------------------------------------------------
 *  (C) Copyright 2013-2024 Travis Montoya
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <getopt.h>
#include <elf.h>

#define MMAP_PARAMS PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS
#define LINE_BREAK   18
#define CODE_SECTION ".text"

#define BLUE "\033[0;33m"
#define GRAY "\033[0;37m"
#define RED  "\033[1;31m"
#define STOP "\033[1;0m"

struct ELFCNTR
{
  int nullcntr;
  int line;
  int data_idx;
};

typedef struct
{
  char sname[6];
  int sections;
  int addrlen;
  int addr;
  struct ELFCNTR cntr;
} ELFDATA;


int parse (char *obj_file, int execute_flag);
int execute_code (unsigned char *ex_shellcode, int shellcode_len);
int usage (char *prog_name);

static int verbose_flag = 0;
static int execute_flag = 0;

int
parse (char *obj_file, int execute_flag)
{
  ELFDATA *elf = NULL;;
  Elf64_Ehdr ehdr;
  Elf64_Shdr *shdr = NULL;

  FILE *obj;

  if ((obj = fopen (obj_file, "r+b")) == NULL)
    {
      fprintf (stderr, "%s[*]%s Unable to open %s, %s.\n", RED, STOP,
	       obj_file, strerror (errno));
      return -1;
    }

  printf ("%s[*]%s Examining %s...\n", GRAY, STOP, obj_file);
  fread (&ehdr, sizeof (ehdr), 1, obj);
  if ((strncmp (ehdr.e_ident, ELFMAG, 4) != 0)
      || ehdr.e_ident[EI_CLASS] != ELFCLASS64)
    {
      printf ("%s[*]%s %s is not a valid 64-Bit ELF object file!\n", RED,
	      STOP, obj_file);
      return -1;
    }

  printf ("%s[*]%s e_ident = 0x7f+ELF, continuing.\n", GRAY, STOP);

  printf ("%s[*]%s e_type = (%d) ", GRAY, STOP, ehdr.e_type);
  switch (ehdr.e_type)
    {
    case ET_NONE:
      printf ("None\n");
      break;
    case ET_REL:
      printf ("Relocatable\n");
      break;
    case ET_EXEC:
      printf ("Executable\n");
      break;
    case ET_DYN:
      printf ("Shared Object\n");
      break;
    case ET_CORE:
      printf ("Core\n");
      break;
    default:
      printf ("Unknown\n");
      break;
    }

  /*
   * - first we loop through the sections finding .text
   * - get size and address of .text section
   * - seek to offest of the data and copy it to a buffer
   * - display shellcode in C format
   * - then execute shellcode
   */
  size_t shdr_size = ehdr.e_shnum * sizeof (Elf64_Shdr);
  shdr = (Elf64_Shdr *) malloc (shdr_size);
  elf = (ELFDATA *) malloc (sizeof (ELFDATA));

  elf->addrlen = 0;
  elf->addr = 0;
  elf->cntr.nullcntr = 0;
  elf->cntr.line = 0;
  elf->cntr.data_idx = 0;

  fseek (obj, ehdr.e_shoff, SEEK_SET);
  fread (shdr, sizeof (*shdr), ehdr.e_shnum, obj);

  while (elf->sections++ < ehdr.e_shnum)
    {

      fseek (obj,
	     shdr[ehdr.e_shstrndx].sh_offset + shdr[elf->sections].sh_name,
	     SEEK_SET);
      fgets (elf->sname, 6, obj);

      if ((strncmp (elf->sname, CODE_SECTION, 5)) != 0)
	continue;
      break;
    }

  elf->addr = shdr[elf->sections].sh_offset;
  elf->addrlen = shdr[elf->sections].sh_size;

  printf
    ("%s[*]%s Found '.text' section at address 0x%08x with length of %d bytes.\n",
     GRAY, STOP, elf->addr, elf->addrlen);
  printf ("%s[*]%s Dumping shellcode.\n", GRAY, STOP);

  fseek (obj, 0L, SEEK_SET);
  fseek (obj, shdr[elf->sections].sh_offset, SEEK_SET);

  unsigned char obj_data[elf->addrlen + 1];

  fgets (obj_data, elf->addrlen + 1, obj);
  printf ("\nshellcode {%s\n\t", BLUE);
  while (elf->cntr.data_idx < elf->addrlen)
    {

      if (strlen (obj_data) < elf->addrlen)
	{
	  if (obj_data[elf->cntr.data_idx] == 0)
	    {
	      elf->cntr.nullcntr++;
	    }
	}

      if (elf->cntr.line >= LINE_BREAK)
	{
	  printf ("\n\t");
	  elf->cntr.line = 0;
	}

      printf ("\\x%02x", obj_data[elf->cntr.data_idx++]);
      elf->cntr.line++;
    }

  printf ("%s\n}\n\n", STOP);

  if (obj != NULL)
    {
      fclose (obj);
    }

  if (elf->cntr.nullcntr > 0)
    {
      printf ("%s[*] WARNING:%s Detected %d null bytes!\n", RED, STOP,
	      elf->cntr.nullcntr);
    }

  if (execute_flag == 1)
    {
      execute_code (obj_data, elf->addrlen);
    }

  free (elf);
  free (shdr);
  return 0;
}

int
execute_code (unsigned char *ex_shellcode, int shellcode_len)
{
  unsigned char *shellcode;

  printf ("%s[*]%s Mapping and copying %d bytes of shellcode to memory.\n",
	  GRAY, STOP, shellcode_len);

  shellcode = (unsigned char *) mmap (0, shellcode_len, MMAP_PARAMS, -1, 0);
  if (shellcode == MAP_FAILED)
    {
      fprintf (stderr, "%s[*]%s mmap error, %s\n", RED, STOP,
	       strerror (errno));
      return -1;
    }
  memcpy (shellcode, ex_shellcode, shellcode_len);

  printf ("%s-->%s Executing shellcode at address %p.\n", GRAY, STOP,
	  shellcode);
  (*(void (*)()) shellcode) ();

  return 0;
}


int
usage (char *prog_name)
{
  printf ("Usage: %s [OPTIONS] filename\n\n", prog_name);
  printf ("Options:\n\n");
  printf ("-h, --help                Display help\n");
  printf ("-e, --execute             Execute shellcode\n");
  printf ("-v, --verbose             Verbose output\n\n");
  printf ("Default: Print C Style shellcode output.\n");
}


int
main (int argc, char *argv[])
{
  int c;

  while (1)
    {
      static struct option long_options[] = {
	{"help", no_argument,               0 , 'h'},
	{"verbose", no_argument, &verbose_flag, 'v'},
	{"execute", no_argument, &execute_flag, 'e'},
	{0, 0, 0}
      };
      int option_index = 0;

      c = getopt_long (argc, argv, "hve", long_options, &option_index);
      if (c == -1)
	break;

      switch (c)
	{
	case 0:
            if (long_options[option_index].flag != 0)
            	break;
	case 'h':
	  usage (argv[0]);
	  exit (0);
	case 'v':
	  verbose_flag = 1;
	  break;
	case 'e':
	  execute_flag = 1;
	  break;
	case '?':
	  break;
	default:
	  abort ();
	}

    }

  if (optind < argc)
    {
      printf
	("Linux 64-Bit mmap based shellcode loader by Travis Montoya (C) Copyright 2013-2024\n");
      parse (argv[optind++], execute_flag);
    }
  else
    {
      printf ("%s: no file specified\nType %s -h for help.\n", argv[0],
	      argv[0]);
    }

  return 0;
}

