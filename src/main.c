/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata.h"
#include "dynamic_load.h"

//#define PRISM_LICENSE_RELEASE

#define PRISM_LICENSE_SO_PATH "/opt/license4.0/lib/"
#define PRISM_LICENSE_SO_NAME "liblicense_valid.so"
#define PRISM_LICENSE_SO_CMD "check_license_valid"

int main(int argc, char **argv)
{

#ifdef PRISM_LICENSE_RELEASE
    int ret = license_load_check(PRISM_LICENSE_SO_PATH, PRISM_LICENSE_SO_NAME, PRISM_LICENSE_SO_CMD);
    if(ret != 1){
        printf("license check [%d], license is invalid\n", ret);
        return ret;
    }
#endif
    return SuricataMain(argc, argv);
}
