//
// Created by iyue on 2020/6/24.
//

#include <iostream>
#include "RedDex.h"

int main() {

	// 1. 准备解析dex文件
	RedDex redDex("classes.dex");
	// 2. 解析String
	redDex.RedStringIds();
	// 3. 解析Type
	redDex.RedTypeIds();
	// 4. 解析Proto方法原型
	redDex.RedProtoIds();
	// 5. 解析Field
	redDex.RedFieldIds();
	// 6. 解析Method
	redDex.RedMethodIds();
	// 7. 解析class
	redDex.RedClassDefItem();
}
