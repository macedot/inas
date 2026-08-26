#include <smb2/libsmb2.h>
#include <smb2/libsmb2-share-enum.h>

int
smb2_share_enum_async(struct smb2_context *smb2, enum SHARE_INFO_enum level,
                      smb2_command_cb cb, void *cb_data)
{
        (void)smb2;
        (void)level;
        (void)cb;
        (void)cb_data;
        return -1;
}
