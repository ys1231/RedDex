//
// Created by iyue on 2020/6/23.
//


// ReSharper disable All
#include "RedDex.h"

RedDex::RedDex(const char *path) {
	// 1. 打开文件
	fstream f(path, ios::binary | ios::in);
	// 2. 返回当前文件的指针
	filebuf *pbuf = f.rdbuf();
	// 3. 获取文件大小
	long size = pbuf->pubseekoff(0, ios::end, ios::in);
	// 4. 恢复文件指针位置
	pbuf->pubseekpos(0, ios::in);
	// 5. 分配文件大小的内存空间
	m_buffer = new char[size];
	// 6. 获取文件内容
	pbuf->sgetn(m_buffer, size);
	m_buffer[size - 1] = '\0';
	// 7. 释放资源
	f.close();
	// 解析文件头
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
	 // 1. 获取String在内存中的偏移
	int offset = m_pdexheader->stringIdsOff;
	// 2. 获取String类型的个数
	int stringSize = m_pdexheader->stringIdsSize;
	// 3. 获取字符串索引首地址
	m_string_ids = (u4*)(m_buffer + offset);
	// 4. 获取 Proto首地址
	m_proto_ids_item = (PProtoIdsItem)(m_buffer + m_pdexheader->protoIdsOff);
}

RedDex::~RedDex() {
	delete[] m_buffer;
	m_buffer = nullptr;
}


string RedDex::printString(uint32_t index,int type)
{
	// 单个字符在内存中的位置=单个字符串偏移[索引字符串] + 内存首地址
	u1* stringoff = (u1*)(m_buffer + m_string_ids[index]);
	// 获取每一个字符串所占多少字节 第一个字节表示整个字符串所占多少字节
	const int size = *(stringoff);
	// 获取字符串 -- bug 以\0结尾原理 异常就完蛋
	char* str = (char*)(stringoff + 1);
	// 显示对应的字符串
	if (type)
		printf("第%d个:\t%s\n", index, str);
	else
		printf("\t%s\n", str);
	return str;
}

string RedDex::printType(uint32_t index, int type)
{
	// 根据type偏移得到 字符串池下标 传入 字符串池 索引对应字符
	//printString((m_pdexheader->typeIdsOff + m_buffer)[index]);
	int * ofset=(int*)(m_pdexheader->typeIdsOff + m_buffer);
	return printString(ofset[index],type);
}

void  RedDex::printProto(uint32_t index, int type) {

	// A:解析method原型
	cout << "Method:";
	printString(m_proto_ids_item[index].shorty_idx, 0);
	// B:解析返回值类型
	cout << "Return type:";
	printType(m_proto_ids_item[index].return_type_idx, 0);

	// C: 判断有没有参数
	if (m_proto_ids_item[index].parameters_off) {
		// 获取TypeList 首地址
		int* TypeListOff = (int *)(m_proto_ids_item[index].parameters_off + m_buffer);
		// 解析参数个数和参数类型
		cout << "VelueSize:" << *TypeListOff << endl;
		// 前4个字节 表示 这个方法有几个参数 后面是 short 类型 typeids的下标
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
	 *   根据书中描述: 文件头中 m_string_ids_size 是字符串个数
	 *   m_string_ids_off是 字符串索引在文件中的偏移 索引是4个字节 一共有几个字符串 就靠索引 和 字符串个数决定 
	 *   通过索引得到字符串首地址偏移  第一个字节代表这个字符串的大小
	 *   根据大小 偏移往后一个字节 取 对应大小的字节 就是这个字符串
	 */
	
	//  // 1. 获取String在内存中的偏移
	// int offset = m_pdexheader->stringIdsOff;
	// // 2. 获取String类型的个数
	// int stringSize = m_pdexheader->stringIdsSize;
	// // 3. 获取字符串索引首地址
	// m_string_ids = (u4*)(m_buffer + offset);
	// 4. 解析所有字符串
	for (int index = 0; index < m_pdexheader->stringIdsSize; index++) {
		
		// 拿到String的偏移地址
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
	 * Type_Ids: 包含所有数据类型
	 * type_ids_off   各种类型的索引偏移
	 * 
	 * 
	 */

	// 1. 获取类型个数
	// 2. 获取类型偏移
	int * ofset=(int*)(m_pdexheader->typeIdsOff + m_buffer);
	// 3. 获取每个类型对应原型
	for(uint32_t i=0;i<m_pdexheader->typeIdsSize;i++){
		// 获取字符串池偏移 对应下标 
		uint32_t index = (uint32_t)*ofset;
		// 显示对应类型
		printString(index,0);
		// 获取下一个类型偏移
		ofset++;
	}
	
}

void RedDex::RedProtoIds()
{
	/*
	 * method:方法原型 string index
	 * return:返回值类型 type index
	 * arg; 参数信息 
	 */

	// 1. 获取 Proto首地址
	PProtoIdsItem proto_ids_item = (PProtoIdsItem)(m_buffer + m_pdexheader->protoIdsOff);

	for(uint32_t i=0;i<m_pdexheader->protoIdsSize;i++){

		printf("第%d个方法\n",i);
		// A:解析method原型
		cout << "Method:";
		printString(proto_ids_item->shorty_idx,0);
		// B:解析返回值类型
		cout << "Return type:";
		printType(proto_ids_item->return_type_idx,0);

		// C: 判断有没有参数
		if (proto_ids_item->parameters_off) {
			// 获取TypeList 首地址
			int* TypeListOff = (int *)(proto_ids_item->parameters_off + m_buffer);
			// 解析参数个数和参数类型
			cout << "VelueSize:" << *TypeListOff<<endl;
			// 前4个字节 表示 这个方法有几个参数 后面是 short 类型 typeids的下标
			short* index = (short*)(TypeListOff + 1);
			for (uint32_t i = 0; i < *TypeListOff; i++) {
				cout << "velue:";
				printType(*index, 0);
				index++;
			}
		}
		else
			cout << "VelueSize: null \n";

		// 索引下一个方法原型
		proto_ids_item++;
	}
	
}

void RedDex::RedFieldIds() {
	/*
	 * // 1. 表示本Filed所属class类型 是 type_ids index
	 * // 2. 表示本Field的类型 type_ids index
	 * // 3. 表示本Field的名称 string_ids index
	 */
	// 1. 获取Field表首地址
	PFieldIdsItem field_ids_item = (PFieldIdsItem)(m_buffer + m_pdexheader->fieldIdsOff);

	for(uint32_t i=0;i<m_pdexheader->fieldIdsSize;i++)
	{
		cout << "第" << i << "个Filed" << endl;
		cout << "本Field所属class:";
		printType(field_ids_item->class_idx,0);
		cout << "本Field的类型:";
		printType(field_ids_item->type_idx, 0);
		cout << "本Field的名称:";
		printString(field_ids_item->name_idx, 0);
		field_ids_item++;
	}
}

void RedDex::RedMethodIds() {
	/*
	 *	class_idx;				// 1. 该method所属class类型 type_ids index
	 * 	proto_idx;				// 2. 该method的原型  Proto_Ids index
	 * 	name_idx;				// 3. 该method名称    String_Ids index
	 */

	PMethodIdsItem method_ids_item = (PMethodIdsItem)(m_buffer + m_pdexheader->methodIdsOff);
	for (uint32_t i = 0; i < m_pdexheader->methodIdsSize; i++)
	{
		cout << "第" << i << "个Method" << endl;
		cout << "该method所属class类型:";
		printType(method_ids_item[i].class_idx, 0);
		cout << "该method的原型:";
		printProto(method_ids_item[i].proto_idx, 0);
		cout << "该method名称:";
		printString(method_ids_item[i].name_idx, 0);
	}
}

void RedDex::RedClassDefItem() {

	/*  ClassDefItem
	 *	class_idx;				// 1. 描述具体的class类型 值是type_ids的index
	 *	access_flags;			// 2. 描述class的访问类型: public final static
	 *	superclass_idx;			// 3. superclass 父类类型 和class_idx一样
	 *	interfaces_off;			// 4. 值为偏移地址.指向class的interdaces 数据结构为type_list class若没有interfaces值为0
	 *	source_file_idx;		// 5. 源代码的文件信息 值是 String_Ids的index若此项缺失 值为 NO_INDEX=0xFFFF FFFFF
	 *	annotions_off;			// 6. 偏移 指向该class的注释,位置在data区 格式为:annotations_directotry_item
	 *	class_data_off;			// 7. 偏移 指向该class用到的数据位置在data区格式为:class_data_item 若没有此项 值为0 --bug 详细描述该class的field,method 里的执行代码等信息 
	 *	static_value_off;		// 8. 偏移 指向daata区的一个列表 格式为: encoded_array_item 若没有此向内容值为0/
	*/

	// 1.获取class_Def_item 首地址
	PClassDefItem class_def_item = (PClassDefItem)(m_buffer + m_pdexheader->classDefsOff);
	// 2. 根据个数遍历
	for(uint32_t i=0;i<m_pdexheader->classDefsSize;i++)
	{
		cout << "-----------begin--------" << endl;
		cout << "class类型:\t";
		printType(class_def_item[i].class_idx, 0);
		







		
		cout << "-----------end--------" << endl;
	}	
}
