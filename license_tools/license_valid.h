#ifndef __LICENSE_VALID_H_
#define __LICENSE_VALID_H_

/*******************
 *FUNC:
 *  mode == 0 默认模式，将在 /etc/prism/生成 验证结果文件 license_valid_result
 *  mode == 1 静默模式，将在 stdout 输出结果.
 *
 *Return:
 *  验证通过返回 1
 *  验证失败返回 -1
 *
 *NOTICE:
 *  可以仅仅通过返回值判断，详细验证结果可以在 /etc/prism/license_valid_result 中查看.
 *
 * ****************/
int check_license_valid(int mode) ;

#endif
