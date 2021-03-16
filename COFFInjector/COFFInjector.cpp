#include <Windows.h>
#include <stdio.h>
#include <coffi\coffi.hpp>

void COFF_API_Print(char* string)
{
	printf("\n___Injected code printing___\n");
	printf(string);
	printf("\n____________________________\n\n");
}

int LoadExecute(char* path)
{
	COFFI::coffi COFF;
	COFF.load(path);

	// Find .text and .drectve sections
	COFFI::sections& sections = COFF.get_sections();
	COFFI::section* textSection, * drectveSection, * rdataSection;
	for (int i = 0; i < sections.size(); i++)
	{
		if (sections[i]->get_name().find(".text") != std::string::npos)
		{
			textSection = sections[i];
		}
		if (sections[i]->get_name().find(".drectve") != std::string::npos)
		{
			drectveSection = sections[i];
		}
		if (sections[i]->get_name().find(".rdata") != std::string::npos)
		{
			rdataSection = sections[i];
		}
	}

	auto textSectionRelocations = textSection->get_relocations();
	auto symbols = COFF.get_symbols();

	// Calculate memory needed for assembly + static data + external function pointers 
	uint32_t totalSize = textSection->get_data_size() + rdataSection->get_data_size();
	for (int i = 0; i < textSectionRelocations.size(); i++)
	{
		COFFI::symbol* symbol = COFF.get_symbol(textSectionRelocations[i].get_symbol_table_index());
		if (symbol->get_storage_class() == IMAGE_SYM_CLASS_EXTERNAL)
		{
			totalSize += sizeof(PVOID);
		}
	}
	PBYTE allData = (PBYTE)VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	PBYTE dataPointer = allData;

	// Copy assembly
	memcpy(allData, textSection->get_data(), textSection->get_data_size());
	dataPointer += textSection->get_data_size();
	printf("Allocated DATA @ %x\n", allData);
	printf("DATA dump (before relocations):\n", allData);
	for (int i = 0; i < totalSize; i++)
	{
		printf("%02X ", allData[i]);
		if ((i % 16) == 15) printf("\n");
	}
	printf("\n\n");

	// Check offsets (sizes) of all static symbols
	std::vector<COFFI::symbol*> staticSymbols;
	for (COFFI::relocation r : textSectionRelocations)
	{
		COFFI::symbol* symbol = COFF.get_symbol(r.get_symbol_table_index());
		if (symbol->get_storage_class() == IMAGE_SYM_CLASS_STATIC)
		{
			staticSymbols.push_back(symbol);
		}
	}

	// Relocate static symbols
	printf("Relocating static symbols\n");
	for (int i = 0; i < staticSymbols.size(); i++)
	{
		COFFI::symbol* s = staticSymbols[i];
		// write data
		COFFI::section* symbolSection = sections[s->get_section_number() - 1];
		const char* dataSource = symbolSection->get_data() + s->get_value();
		uint32_t dataSize;
		if (i == (staticSymbols.size() - 1))
		{
			dataSize = symbolSection->get_data_size() - s->get_value(); // last element size == section size - last element offset
		}
		else
		{
			dataSize = (s + 1)->get_value() - s->get_value(); // current element size == next element offset - current element offset
		}
		memcpy(dataPointer, dataSource, dataSize);
		printf("Written static data @ %x : 0x%x bytes\n", dataPointer, dataSize);

		// overwrite local addresses in assembly
		for (COFFI::relocation r : textSectionRelocations)
		{
			COFFI::symbol* rs = COFF.get_symbol(r.get_symbol_table_index());
			if ((rs->get_storage_class() == IMAGE_SYM_CLASS_STATIC) && (rs->get_index() == s->get_index()))
			{
				uint64_t symbolOffset = dataPointer - allData - r.get_virtual_address() - 4;
				memcpy(allData + r.get_virtual_address(), &symbolOffset, 4);
				printf("Relocated symbol: %s : offset = 0x%x -> %x\n", rs->get_name().c_str(), symbolOffset, allData + r.get_virtual_address());
			}
		}
		dataPointer += dataSize;
	}

	//  Resolve external functions
	printf("\nRelocating external symbols\n");
	for (COFFI::relocation r : textSectionRelocations)
	{
		COFFI::symbol* symbol = COFF.get_symbol(r.get_symbol_table_index());
		uint16_t symbolSectionNo = symbol->get_section_number();
		uint16_t symbolType = symbol->get_type();
		if (symbol->get_storage_class() == IMAGE_SYM_CLASS_EXTERNAL)
		{
			std::string libraryDirective, libraryName, functionName = symbol->get_name();
			if (functionName.substr(0, 6) == "__imp_")
			{
				functionName = functionName.substr(6); // strip '__imp_'
			}
			printf("Searching %s ...\n", functionName.c_str());
			libraryDirective.append(drectveSection->get_data());
			size_t pos2 = 0, pos3 = 0, pos1 = libraryDirective.find("/DEFAULTLIB:\"");
			while (pos1 != std::string::npos)
			{
				pos2 = pos1 + 13;
				pos3 = libraryDirective.find("\"", pos2);
				libraryName = libraryDirective.substr(pos2, pos3 - pos2);
				libraryName.pop_back(); libraryName.pop_back(); libraryName.pop_back(); // remove 'lib' extension
				libraryName.append("dll");
				HMODULE hLibrary = LoadLibraryA(libraryName.c_str());
				if (hLibrary)
				{
					PVOID functionPointer = GetProcAddress(hLibrary, functionName.c_str());
					if (functionPointer)
					{
						// write module address
						printf("Function %s @ %llx in %s\n", functionName.c_str(), functionPointer, libraryName.c_str());
						memcpy(dataPointer, &functionPointer, 8);

						// overwrite local address in assembly
						uint64_t functionAddressOffset = dataPointer - allData - r.get_virtual_address() - 4;
						memcpy(allData + r.get_virtual_address(), &functionAddressOffset, 4);
						dataPointer += 8;
						break;
					}
				}
				pos1 = libraryDirective.find("/DEFAULTLIB:\"", pos2 + 1);
			}
			if (functionName.find("COFF_API_Print") != std::string::npos)
			{
				printf("Function %s @ %llx\n", functionName.c_str(), &COFF_API_Print);
				PVOID addr = &COFF_API_Print;
				PVOID addrOfAddr = &addr;
				memcpy(dataPointer, addrOfAddr, 8);
				uint64_t functionAddressOffset = dataPointer - allData - r.get_virtual_address() - 4;
				memcpy(allData + r.get_virtual_address(), &functionAddressOffset, 4);
				dataPointer += 8;
			}
		}
	}

	printf("\n");
	printf("DATA dump (after relocations):\n", allData);
	for (int i = 0; i < totalSize; i++)
	{
		printf("%02X ", allData[i]);
		if ((i % 16) == 15) printf("\n");
	}
	printf("\n");

	int returnedValue = ((int(*)())allData)();
	printf("Injected funtion main() returned: %d\n", returnedValue);

	return 0;
}

int main(int argc, char** argv)
{
	LoadExecute(argv[1]);
	return 0;
}
