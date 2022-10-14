
void MonikaCreateFile(PUNICODE_STRING FILEPATH)
{
	DbgPrint("Entered MonikaCreateFile %wZ", FILEPATH);
	OBJECT_ATTRIBUTES objAttr;
	HANDLE handle;
	IO_STATUS_BLOCK ioStatus;

	InitializeObjectAttributes(&objAttr, FILEPATH, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ZwCreateFile(&handle, GENERIC_ALL, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	ZwClose(&handle);

	return;
}

void MonikaDeleteFile(PUNICODE_STRING FILEPATH)
{
	DbgPrint("Entered MonikaDeleteFile %wZ", FILEPATH);
	OBJECT_ATTRIBUTES objAttr;
	HANDLE handle;
	IO_STATUS_BLOCK ioStatus;

	InitializeObjectAttributes(&objAttr, FILEPATH, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	//Delete the File
	ZwCreateFile(&handle, DELETE, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	ZwClose(&handle);
	
	return;
}