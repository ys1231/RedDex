//
// Created by iyue on 2020/6/23.
// 参考书籍: Android应用安全防护和逆向分析-姜维
//

// ReSharper disable All
#ifndef REDDEXFILE_REDDEX_H
#define REDDEXFILE_REDDEX_H
#include <fstream>
#include <iostream>
using namespace std;

// 自定义类型
typedef uint8_t  u1;
typedef uint16_t u2;
typedef uint32_t u4;

enum {
	// SHA1 签名的大小20字节
	kSHA1DigestLen = 20
};

// 文件头结构体
typedef struct _DexHeader {

	u1 magic[8];                    // 1. 魔数 文件标识的版本号 8个字节
	u4 checksum;                    // 2. 文件校验码 alder32 算法
	u1 signature[kSHA1DigestLen];   // 3. 文件签名去除前三个 SHA-1算法
	u4 fileSize;                    // 4. dex文件长度 单位字节
	u4 headerSize;                  // 5. dex文件头大小 (默认0x70)
	u4 endanTag;                    // 6. 文件大小端标签 (标准为小端一般固定为 0x 12345678)
	u4 linkSize;                    // 7. 链接数据的大小
	u4 linkOff;                     // 8. 链接数据的偏移
	u4  mapOff;                     // 9. map item的偏移地址,该item属于data区里的内值要大于等于date_off的大小
	u4 stringIdsSize;               // 10. dex中所有字符串内容的大小
	u4 stringIdsOff;                // 11. 偏移 其它数据结构使用索引来访问字符串池
	u4 typeIdsSize;                 // 12. dex中的类型数据结构的大小
	u4 typeIdsOff;                  // 13. 偏移 比如类类型,基本类型等信息
	u4 protoIdsSize;                // 14. dex中元数据信息数据结构的大小
	u4 protoIdsOff;                 // 15. 偏移 比如方法的返回类型,参数类型等信息
	u4 fieldIdsSize;                // 16. dex中字段信息的数据结构大小
	u4 fieldIdsOff;                 // 17. 偏移
	u4 methodIdsSize;               // 18. dex中方法信息数据结构的大小
	u4 methodIdsOff;                // 29. 偏移
	u4 classDefsSize;               // 20. dex中类信息数据结构的大小
	u4 classDefsOff;                // 21. 偏移 内部层次很深 包含很多其它数据结构
	u4 dataSize;                    // 22. dex中数据区域的结构信息的大小
	u4 dateOff;                     // 23. 偏移 比如定义的常量值等信息

}DEXHEADER, *PDEXHEADER;

// protoIdsItem
typedef struct _ProtoIdsItem
{
	u4 shorty_idx = 0;			// 1. 索引string
	u4 return_type_idx = 0;		// 2. 索引type
	u4 parameters_off = 0;		// 3. 偏移 里面是 4字节 个数 和 2字节下标
}ProtoIdsItem,*PProtoIdsItem;

// FieldIdsItem
typedef struct _FiledIdsItem
{
	u2 class_idx;				// 1. 表示本Filed所属class类型 是 type_ids index
	u2 type_idx;				// 2. 表示本Field的类型
	u4 name_idx;				// 3. 表示本Field的名称
	
}FieldIdsItem,*PFieldIdsItem;

// MethodIdsItem
typedef struct _MethodIdsItem
{
	u2 class_idx;				// 1. 该method所属class类型 type_ids index
 	u2 proto_idx;				// 2. 该method的原型  Proto_Ids index
	u4 name_idx;				// 3. 该method名称    String_Ids index
}MethodIdsItem,*PMethodIdsItem;

// ClassDefItem
typedef struct _ClassDefItem
{
	u4 class_idx;				// 1. 描述具体的class类型 值是type_ids的index
	u4 access_flags;			// 2. 描述class的访问类型: public final static
	u4 superclass_idx;			// 3. superclass 父类类型 和class_idx一样
	u4 interfaces_off;			// 4. 值为偏移地址.指向class的interdaces 数据结构为type_list class若没有interfaces值为0
	u4 source_file_idx;			// 5. 源代码的文件信息 值是 String_Ids的index若此项缺失 值为 NO_INDEX=0xFFFF FFFFF
	u4 annotions_off;			// 6. 偏移 指向该class的注释,位置在data区 格式为:annotations_directotry_item
	u4 class_data_off;			// 7. 偏移 指向该class用到的数据位置在data区格式为:class_data_item 若没有此项 值为0 --bug 详细描述该class的field,method 里的执行代码等信息
	u4 static_value_off;		// 8. 偏移 指向daata区的一个列表 格式为: encoded_array_item 若没有此向内容值为0

}ClassDefItem,*PClassDefItem;

class RedDex {
public:
	// 构造函数 自动解析文件头
	RedDex(const char * path);
	~RedDex();

private:
	// 存放读取的文件内容
	char* m_buffer;
	// 文件头指针方便其他数据解析
	PDEXHEADER m_pdexheader;
	// 字符串索引首地址
	u4* m_string_ids;
	// Proto首地址
	PProtoIdsItem m_proto_ids_item;
	
	// tools
	// 根据下标输出字符串 type: 是否打印索引 1 默认需要
	string printString(uint32_t index,int type=1);
	// 根据下标输出类型字符串
	string printType(uint32_t index, int type = 1);
	// 根据下标输出Proto
	void printProto(uint32_t index, int type = 1);
public:
	// 解析string_ids
	void RedStringIds();
	// 解析type_ids
	void RedTypeIds();
	// 解析proto_ids
	void RedProtoIds();
	// 解析Feild_ids
	void RedFieldIds();
	// 解析Method_ids
	void RedMethodIds();
	// 解析class_def_item
	void RedClassDefItem();
};


#endif //REDDEXFILE_REDDEX_H

