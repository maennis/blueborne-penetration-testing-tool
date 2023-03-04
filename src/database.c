#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "database.h"

void close_db(sqlite3 *db)
{
    sqlite3_close_v2(db);
}

int get_manuafacturer_from_oui(sqlite3 *db, char *btaddr_s, char *manufacturer)
{
    sqlite3_stmt *res;
    char *oui, pattern[OUI_LEN + 2] = { 0 }, *query = "SELECT Vendor_Name FROM prefixes WHERE Mac_Prefix LIKE ?";
    int r;
    // Allocate memory for the OUI and copy it from the BT address
    oui = (char *) malloc(OUI_LEN);
    memset(oui, 0, OUI_LEN);
    strncpy(oui, btaddr_s, OUI_LEN - 1);
    // Create the search pattern with the OUI
    pattern[0] = '%';
    strncpy(pattern + 1, oui, OUI_LEN - 1);
    pattern[OUI_LEN] = '%';

    r = sqlite3_prepare_v2(db, query, -1, &res, 0);
    if (r != SQLITE_OK)
    {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(res);
        return 0;
    }
    
    sqlite3_bind_text(res, 1, pattern, -1, 0);
    r = sqlite3_step(res);

    if(r != SQLITE_ROW)
    {
        fprintf(stderr, "Failed to retrieve data: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(res);
        return 0;
    }
    strcpy(manufacturer, sqlite3_column_text(res, 0));

    sqlite3_finalize(res);
    return 1;
}

sqlite3 * open_db(char *dbname)
{
    sqlite3 *db;
    int r = sqlite3_open_v2(dbname, &db, SQLITE_OPEN_READWRITE, 0);
    if (r != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    return db;
}
