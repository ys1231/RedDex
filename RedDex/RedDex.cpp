//
// Created by iyue on 2020/6/23.
//


// ReSharper disable All
#include "RedDex.h"

RedDex::RedDex(const char *path) {
	// 1. ���ļ�
	fstream f(path, ios::binary | ios::in);
	// 2. ���ص�ǰ�ļ���ָ��
	filebuf *pbuf = f.rdbuf();
	// 3. ��ȡ�ļ���С
	long size = pbuf->pubseekoff(0, ios::end, ios::in);
	// 4. �ָ��ļ�ָ��λ��
	pbuf->pubseekpos(0, ios::in);
	// 5. �����ļ���С���ڴ�ռ�
	m_buffer = new char[size];
	// 6. ��ȡ�ļ�����
	pbuf->sgetn(m_buffer, size);
	m_buffer[size - 1] = '\0';
	// 7. �ͷ���Դ
	f.close();
	// �����ļ�ͷ
	m_pdexheader = (PDEXHEADER)m_buffer;
	cout << "start anlisys:" << endl;
	cout << "magic:" << m_pdexheader->magic << endl;
	cout << "checksum:" << m_pdexheader->checksum << endl;
	cout << "signature:" << hex << m_pdexheader->signature << endl;
	cout << "fileSize:" << hex << m_pdexheader->fileSize << endl;
	cout << "headerSize:" << m_pdexheader->headerSize << endl;
	cout << "endanTag:" << m_pdexheader->endanTag << endl;
	cout << "linkSize:" << m_pdexheader->linkSize << endl;
	cout << "linkOff:" << m_pdexheader->linkOff << endl;
	cout << "mapOff:" << m_pdexheader->mapOff << endl;
	cout << "stringIdsSize:" << m_pdexheader->stringIdsSize << endl;
	cout << "stringIdsOff:" << m_pdexheader->stringIdsOff << endl;
	cout << "typeIdsSize:" << m_pdexheader->typeIdsSize << endl;
	cout << "typeIdsOff:" << m_pdexheader->typeIdsOff << endl;
	cout << "protoIdsSize:" << m_pdexheader->protoIdsSize << endl;
	cout << "protoIdsOff:" << m_pdexheader->protoIdsOff << endl;
	cout << "fieldIdsSize:" << m_pdexheader->fieldIdsSize << endl;
	cout << "fieldIdsOff:" << m_pdexheader->fieldIdsOff << endl;
	cout << "methodIdsSize:" << m_pdexheader->methodIdsSize << endl;
	cout << "methodIdsOff:" << m_pdexheader->methodIdsOff << endl;
	cout << "classDefsSize:" << m_pdexheader->classDefsSize << endl;
	cout << "classDefsOff:" << m_pdexheader->classDefsOff << endl;
	cout << "dataSize:" << m_pdexheader->dataSize << endl;
	cout << "dateOff:" << m_pdexheader->dateOff << endl;

	// other init
	 // 1. ��ȡString���ڴ��е�ƫ��
	int offset = m_pdexheader->stringIdsOff;
	// 2. ��ȡString���͵ĸ���
	int stringSize = m_pdexheader->stringIdsSize;
	// 3. ��ȡ�ַ��������׵�ַ
	m_string_ids = (u4*)(m_buffer + offset);
	// 4. ��ȡ Proto�׵�ַ
	m_proto_ids_item = (PProtoIdsItem)(m_buffer + m_pdexheader->protoIdsOff);
}

RedDex::~RedDex() {
	delete[] m_buffer;
	m_buffer = nullptr;
}


string RedDex::printString(uint32_t index,int type)
{
	// �����ַ����ڴ��е�λ��=�����ַ���ƫ��[�����ַ���] + �ڴ��׵�ַ
	u1* stringoff = (u1*)(m_buffer + m_string_ids[index]);
	// ��ȡÿһ���ַ�����ռ�����ֽ� ��һ���ֽڱ�ʾ�����ַ�����ռ�����ֽ�
	const int size = *(stringoff);
	// ��ȡ�ַ��� -- bug ��\0��βԭ�� �쳣���군
	char* str = (char*)(stringoff + 1);
	// ��ʾ��Ӧ���ַ���
	if (type)
		printf("��%d��:\t%s\n", index, str);
	else
		printf("\t%s\n", str);
	return str;
}

string RedDex::printType(uint32_t index, int type)
{
	// ����typeƫ�Ƶõ� �ַ������±� ���� �ַ����� ������Ӧ�ַ�
	//printString((m_pdexheader->typeIdsOff + m_buffer)[index]);
	int * ofset=(int*)(m_pdexheader->typeIdsOff + m_buffer);
	return printString(ofset[index],type);
}

void  RedDex::printProto(uint32_t index, int type) {

	// A:����methodԭ��
	cout << "Method:";
	printString(m_proto_ids_item[index].shorty_idx, 0);
	// B:��������ֵ����
	cout << "Return type:";
	printType(m_proto_ids_item[index].return_type_idx, 0);

	// C: �ж���û�в���
	if (m_proto_ids_item[index].parameters_off) {
		// ��ȡTypeList �׵�ַ
		int* TypeListOff = (int *)(m_proto_ids_item[index].parameters_off + m_buffer);
		// �������������Ͳ�������
		cout << "VelueSize:" << *TypeListOff << endl;
		// ǰ4���ֽ� ��ʾ ��������м������� ������ short ���� typeids���±�
		short* index = (short*)(TypeListOff + 1);
		for (uint32_t i = 0; i < *TypeListOff; i++) {
			cout << "velue:";
			printType(*index, 0);
			index++;
		}
	}
	else
		cout << "VelueSize: null \n";
;
}

void RedDex::RedStringIds() {

	/*
	 *   ������������: �ļ�ͷ�� m_string_ids_size ���ַ�������
	 *   m_string_ids_off�� �ַ����������ļ��е�ƫ�� ������4���ֽ� һ���м����ַ��� �Ϳ����� �� �ַ����������� 
	 *   ͨ�������õ��ַ����׵�ַƫ��  ��һ���ֽڴ�������ַ����Ĵ�С
	 *   ���ݴ�С ƫ������һ���ֽ� ȡ ��Ӧ��С���ֽ� ��������ַ���
	 */
	
	//  // 1. ��ȡString���ڴ��е�ƫ��
	// int offset = m_pdexheader->stringIdsOff;
	// // 2. ��ȡString���͵ĸ���
	// int stringSize = m_pdexheader->stringIdsSize;
	// // 3. ��ȡ�ַ��������׵�ַ
	// m_string_ids = (u4*)(m_buffer + offset);
	// 4. ���������ַ���
	for (int index = 0; index < m_pdexheader->stringIdsSize; index++) {
		
		// �õ�String��ƫ�Ƶ�ַ
		//printf("%d", *m_string_ids);
		printString(index);
		
		//char* str = new char[size];
		//memcpy(str, stringoff + 1, size);
	
		
		
		//delete[] str;
		//str = NULL;
	}
}

void RedDex::RedTypeIds(){
	/*
	 * Type_Ids: ����������������
	 * type_ids_off   �������͵�����ƫ��
	 * 
	 * 
	 */

	// 1. ��ȡ���͸���
	// 2. ��ȡ����ƫ��
	int * ofset=(int*)(m_pdexheader->typeIdsOff + m_buffer);
	// 3. ��ȡÿ�����Ͷ�Ӧԭ��
	for(uint32_t i=0;i<m_pdexheader->typeIdsSize;i++){
		// ��ȡ�ַ�����ƫ�� ��Ӧ�±� 
		uint32_t index = (uint32_t)*ofset;
		// ��ʾ��Ӧ����
		printString(index,0);
		// ��ȡ��һ������ƫ��
		ofset++;
	}
	
}

void RedDex::RedProtoIds()
{
	/*
	 * method:����ԭ�� string index
	 * return:����ֵ���� type index
	 * arg; ������Ϣ 
	 */

	// 1. ��ȡ Proto�׵�ַ
	PProtoIdsItem proto_ids_item = (PProtoIdsItem)(m_buffer + m_pdexheader->protoIdsOff);

	for(uint32_t i=0;i<m_pdexheader->protoIdsSize;i++){

		printf("��%d������\n",i);
		// A:����methodԭ��
		cout << "Method:";
		printString(proto_ids_item->shorty_idx,0);
		// B:��������ֵ����
		cout << "Return type:";
		printType(proto_ids_item->return_type_idx,0);

		// C: �ж���û�в���
		if (proto_ids_item->parameters_off) {
			// ��ȡTypeList �׵�ַ
			int* TypeListOff = (int *)(proto_ids_item->parameters_off + m_buffer);
			// �������������Ͳ�������
			cout << "VelueSize:" << *TypeListOff<<endl;
			// ǰ4���ֽ� ��ʾ ��������м������� ������ short ���� typeids���±�
			short* index = (short*)(TypeListOff + 1);
			for (uint32_t i = 0; i < *TypeListOff; i++) {
				cout << "velue:";
				printType(*index, 0);
				index++;
			}
		}
		else
			cout << "VelueSize: null \n";

		// ������һ������ԭ��
		proto_ids_item++;
	}
	
}

void RedDex::RedFieldIds() {
	/*
	 * // 1. ��ʾ��Filed����class���� �� type_ids index
	 * // 2. ��ʾ��Field������ type_ids index
	 * // 3. ��ʾ��Field������ string_ids index
	 */
	// 1. ��ȡField���׵�ַ
	PFieldIdsItem field_ids_item = (PFieldIdsItem)(m_buffer + m_pdexheader->fieldIdsOff);

	for(uint32_t i=0;i<m_pdexheader->fieldIdsSize;i++)
	{
		cout << "��" << i << "��Filed" << endl;
		cout << "��Field����class:";
		printType(field_ids_item->class_idx,0);
		cout << "��Field������:";
		printType(field_ids_item->type_idx, 0);
		cout << "��Field������:";
		printString(field_ids_item->name_idx, 0);
		field_ids_item++;
	}
}

void RedDex::RedMethodIds() {
	/*
	 *	class_idx;				// 1. ��method����class���� type_ids index
	 * 	proto_idx;				// 2. ��method��ԭ��  Proto_Ids index
	 * 	name_idx;				// 3. ��method����    String_Ids index
	 */

	PMethodIdsItem method_ids_item = (PMethodIdsItem)(m_buffer + m_pdexheader->methodIdsOff);
	for (uint32_t i = 0; i < m_pdexheader->methodIdsSize; i++)
	{
		cout << "��" << i << "��Method" << endl;
		cout << "��method����class����:";
		printType(method_ids_item[i].class_idx, 0);
		cout << "��method��ԭ��:";
		printProto(method_ids_item[i].proto_idx, 0);
		cout << "��method����:";
		printString(method_ids_item[i].name_idx, 0);
	}
}

void RedDex::RedClassDefItem() {

	/*  ClassDefItem
	 *	class_idx;				// 1. ���������class���� ֵ��type_ids��index
	 *	access_flags;			// 2. ����class�ķ�������: public final static
	 *	superclass_idx;			// 3. superclass �������� ��class_idxһ��
	 *	interfaces_off;			// 4. ֵΪƫ�Ƶ�ַ.ָ��class��interdaces ���ݽṹΪtype_list class��û��interfacesֵΪ0
	 *	source_file_idx;		// 5. Դ������ļ���Ϣ ֵ�� String_Ids��index������ȱʧ ֵΪ NO_INDEX=0xFFFF FFFFF
	 *	annotions_off;			// 6. ƫ�� ָ���class��ע��,λ����data�� ��ʽΪ:annotations_directotry_item
	 *	class_data_off;			// 7. ƫ�� ָ���class�õ�������λ����data����ʽΪ:class_data_item ��û�д��� ֵΪ0 --bug ��ϸ������class��field,method ���ִ�д������Ϣ 
	 *	static_value_off;		// 8. ƫ�� ָ��daata����һ���б� ��ʽΪ: encoded_array_item ��û�д�������ֵΪ0/
	*/

	// 1.��ȡclass_Def_item �׵�ַ
	PClassDefItem class_def_item = (PClassDefItem)(m_buffer + m_pdexheader->classDefsOff);
	// 2. ���ݸ�������
	for(uint32_t i=0;i<m_pdexheader->classDefsSize;i++)
	{
		cout << "-----------begin--------" << endl;
		cout << "class����:\t";
		printType(class_def_item[i].class_idx, 0);
		







		
		cout << "-----------end--------" << endl;
	}	
}
