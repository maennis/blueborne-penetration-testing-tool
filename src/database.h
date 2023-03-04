#include <sqlite3.h>

#define OUI_LEN         9
#define MAX_VENDOR_LEN  110

void close_db(sqlite3* db);

int get_manuafacturer_from_oui(sqlite3 *db, char *btaddr_s, char *manufacturer);

sqlite3 * open_db(char * dbname);
