//
// Created by iyue on 2020/6/24.
//

#include <iostream>
#include "RedDex.h"

int main() {

	// 1. ׼������dex�ļ�
	RedDex redDex("classes.dex");
	// 2. ����String
	redDex.RedStringIds();
	// 3. ����Type
	redDex.RedTypeIds();
	// 4. ����Proto����ԭ��
	redDex.RedProtoIds();
	// 5. ����Field
	redDex.RedFieldIds();
	// 6. ����Method
	redDex.RedMethodIds();
	// 7. ����class
	redDex.RedClassDefItem();
}
