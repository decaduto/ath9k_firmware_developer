MEMORY
{
  rom      (rwx)  : ORIGIN = 0x0000, LENGTH = 0x00040000
}

SECTIONS
{
    .firmware :
	{

	} > rom
}
