
void MonikaCreateFile(LPWCH path)
{
	DbgPrint("Entered MonikaCreateFile");
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING FILEPATH = RTL_CONSTANT_STRING(path);
	HANDLE handle;
	IO_STATUS_BLOCK ioStatus;

	InitializeObjectAttributes(&objAttr, &FILEPATH, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ZwCreateFile(&handle, GENERIC_ALL, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	ZwClose(&handle);

	return;
}

void MonikaDeleteFile(LPWCH path)
{
	DbgPrint("Entered MonikaDeleteFile");
	return;
}