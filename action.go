package security

const (
	ActionNone     int32 = 0
	ActionView     int32 = 1
	ActionSearch   int32 = 2
	ActionQueryAll int32 = 4
	ActionViewAll  int32 = 256 - 1
	ActionAdd      int32 = 256
	ActionEdit     int32 = 512
	ActionPatch    int32 = 1024
	ActionApprove  int32 = 2048
	ActionReject   int32 = 4096
	ActionDelete   int32 = 32768
	ActionWriteAll int32 = 65536 - 1
	ActionAll      int32 = 2147483647

	ActionViewAllView        int32 = ActionViewAll | ActionView
	ActionSearchView         int32 = ActionSearch | ActionView
	ActionAddEdit            int32 = ActionAdd | ActionEdit
	ActionAddEditPatch       int32 = ActionAdd | ActionEdit | ActionPatch
	ActionEditPatch          int32 = ActionEdit | ActionPatch
	ActionApproveReject      int32 = ActionApprove | ActionReject
	ActionAddEditPatchDelete int32 = ActionAdd | ActionEdit | ActionPatch | ActionDelete
)
