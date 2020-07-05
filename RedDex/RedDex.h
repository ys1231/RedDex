//
// Created by iyue on 2020/6/23.
// �ο��鼮: AndroidӦ�ð�ȫ�������������-��ά
//

// ReSharper disable All
#ifndef REDDEXFILE_REDDEX_H
#define REDDEXFILE_REDDEX_H
#include <fstream>
#include <iostream>
using namespace std;

// �Զ�������
typedef uint8_t  u1;
typedef uint16_t u2;
typedef uint32_t u4;

enum {
	// SHA1 ǩ���Ĵ�С20�ֽ�
	kSHA1DigestLen = 20
};

// �ļ�ͷ�ṹ��
typedef struct _DexHeader {

	u1 magic[8];                    // 1. ħ�� �ļ���ʶ�İ汾�� 8���ֽ�
	u4 checksum;                    // 2. �ļ�У���� alder32 �㷨
	u1 signature[kSHA1DigestLen];   // 3. �ļ�ǩ��ȥ��ǰ���� SHA-1�㷨
	u4 fileSize;                    // 4. dex�ļ����� ��λ�ֽ�
	u4 headerSize;                  // 5. dex�ļ�ͷ��С (Ĭ��0x70)
	u4 endanTag;                    // 6. �ļ���С�˱�ǩ (��׼ΪС��һ��̶�Ϊ 0x 12345678)
	u4 linkSize;                    // 7. �������ݵĴ�С
	u4 linkOff;                     // 8. �������ݵ�ƫ��
	u4  mapOff;                     // 9. map item��ƫ�Ƶ�ַ,��item����data�������ֵҪ���ڵ���date_off�Ĵ�С
	u4 stringIdsSize;               // 10. dex�������ַ������ݵĴ�С
	u4 stringIdsOff;                // 11. ƫ�� �������ݽṹʹ�������������ַ�����
	u4 typeIdsSize;                 // 12. dex�е��������ݽṹ�Ĵ�С
	u4 typeIdsOff;                  // 13. ƫ�� ����������,�������͵���Ϣ
	u4 protoIdsSize;                // 14. dex��Ԫ������Ϣ���ݽṹ�Ĵ�С
	u4 protoIdsOff;                 // 15. ƫ�� ���緽���ķ�������,�������͵���Ϣ
	u4 fieldIdsSize;                // 16. dex���ֶ���Ϣ�����ݽṹ��С
	u4 fieldIdsOff;                 // 17. ƫ��
	u4 methodIdsSize;               // 18. dex�з�����Ϣ���ݽṹ�Ĵ�С
	u4 methodIdsOff;                // 29. ƫ��
	u4 classDefsSize;               // 20. dex������Ϣ���ݽṹ�Ĵ�С
	u4 classDefsOff;                // 21. ƫ�� �ڲ���κ��� �����ܶ��������ݽṹ
	u4 dataSize;                    // 22. dex����������Ľṹ��Ϣ�Ĵ�С
	u4 dateOff;                     // 23. ƫ�� ���綨��ĳ���ֵ����Ϣ

}DEXHEADER, *PDEXHEADER;

// protoIdsItem
typedef struct _ProtoIdsItem
{
	u4 shorty_idx = 0;			// 1. ����string
	u4 return_type_idx = 0;		// 2. ����type
	u4 parameters_off = 0;		// 3. ƫ�� ������ 4�ֽ� ���� �� 2�ֽ��±�
}ProtoIdsItem,*PProtoIdsItem;

// FieldIdsItem
typedef struct _FiledIdsItem
{
	u2 class_idx;				// 1. ��ʾ��Filed����class���� �� type_ids index
	u2 type_idx;				// 2. ��ʾ��Field������
	u4 name_idx;				// 3. ��ʾ��Field������
	
}FieldIdsItem,*PFieldIdsItem;

// MethodIdsItem
typedef struct _MethodIdsItem
{
	u2 class_idx;				// 1. ��method����class���� type_ids index
 	u2 proto_idx;				// 2. ��method��ԭ��  Proto_Ids index
	u4 name_idx;				// 3. ��method����    String_Ids index
}MethodIdsItem,*PMethodIdsItem;

// ClassDefItem
typedef struct _ClassDefItem
{
	u4 class_idx;				// 1. ���������class���� ֵ��type_ids��index
	u4 access_flags;			// 2. ����class�ķ�������: public final static
	u4 superclass_idx;			// 3. superclass �������� ��class_idxһ��
	u4 interfaces_off;			// 4. ֵΪƫ�Ƶ�ַ.ָ��class��interdaces ���ݽṹΪtype_list class��û��interfacesֵΪ0
	u4 source_file_idx;			// 5. Դ������ļ���Ϣ ֵ�� String_Ids��index������ȱʧ ֵΪ NO_INDEX=0xFFFF FFFFF
	u4 annotions_off;			// 6. ƫ�� ָ���class��ע��,λ����data�� ��ʽΪ:annotations_directotry_item
	u4 class_data_off;			// 7. ƫ�� ָ���class�õ�������λ����data����ʽΪ:class_data_item ��û�д��� ֵΪ0 --bug ��ϸ������class��field,method ���ִ�д������Ϣ
	u4 static_value_off;		// 8. ƫ�� ָ��daata����һ���б� ��ʽΪ: encoded_array_item ��û�д�������ֵΪ0

}ClassDefItem,*PClassDefItem;

class RedDex {
public:
	// ���캯�� �Զ������ļ�ͷ
	RedDex(const char * path);
	~RedDex();

private:
	// ��Ŷ�ȡ���ļ�����
	char* m_buffer;
	// �ļ�ͷָ�뷽���������ݽ���
	PDEXHEADER m_pdexheader;
	// �ַ��������׵�ַ
	u4* m_string_ids;
	// Proto�׵�ַ
	PProtoIdsItem m_proto_ids_item;
	
	// tools
	// �����±�����ַ��� type: �Ƿ��ӡ���� 1 Ĭ����Ҫ
	string printString(uint32_t index,int type=1);
	// �����±���������ַ���
	string printType(uint32_t index, int type = 1);
	// �����±����Proto
	void printProto(uint32_t index, int type = 1);
public:
	// ����string_ids
	void RedStringIds();
	// ����type_ids
	void RedTypeIds();
	// ����proto_ids
	void RedProtoIds();
	// ����Feild_ids
	void RedFieldIds();
	// ����Method_ids
	void RedMethodIds();
	// ����class_def_item
	void RedClassDefItem();
};


#endif //REDDEXFILE_REDDEX_H

