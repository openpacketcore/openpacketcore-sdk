/* Independent host-header oracle for native notification layout, not wire
 * encoding. Compile with cc -std=c11 -Wall -Wextra -Werror and run in CI. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/sctp.h>

#define FIELD(type, field, offset) _Static_assert(offsetof(struct type, field) == offset, #type "." #field)
#define VALUE(symbol, value) _Static_assert(symbol == value, #symbol)
#define SIZE(type, size) _Static_assert(sizeof(struct type) == size, #type)

VALUE(SCTP_PARTIAL_DELIVERY_EVENT, 0x8006);
VALUE(SCTP_STREAM_RESET_EVENT, 0x800a);
VALUE(SCTP_ASSOC_RESET_EVENT, 0x800b);
VALUE(SCTP_STREAM_CHANGE_EVENT, 0x800c);
VALUE(SCTP_STREAM_RESET_INCOMING_SSN, 1);
VALUE(SCTP_STREAM_RESET_OUTGOING_SSN, 2);
VALUE(SCTP_STREAM_RESET_DENIED, 4);
VALUE(SCTP_STREAM_RESET_FAILED, 8);
VALUE(SCTP_ASSOC_RESET_DENIED, 4);
VALUE(SCTP_ASSOC_RESET_FAILED, 8);
VALUE(SCTP_STREAM_CHANGE_DENIED, 4);
VALUE(SCTP_STREAM_CHANGE_FAILED, 8);
VALUE(SCTP_PARTIAL_DELIVERY_ABORTED, 0);
VALUE(SCTP_COMM_UP, 0);
VALUE(SCTP_COMM_LOST, 1);
VALUE(SCTP_RESTART, 2);
VALUE(SCTP_SHUTDOWN_COMP, 3);
VALUE(SCTP_CANT_STR_ASSOC, 4);
SIZE(sctp_stream_reset_event, 12);
FIELD(sctp_stream_reset_event, strreset_assoc_id, 8);
FIELD(sctp_stream_reset_event, strreset_stream_list, 12);
SIZE(sctp_assoc_reset_event, 20);
FIELD(sctp_assoc_reset_event, assocreset_assoc_id, 8);
FIELD(sctp_assoc_reset_event, assocreset_local_tsn, 12);
FIELD(sctp_assoc_reset_event, assocreset_remote_tsn, 16);
SIZE(sctp_stream_change_event, 16);
FIELD(sctp_stream_change_event, strchange_assoc_id, 8);
FIELD(sctp_stream_change_event, strchange_instrms, 12);
FIELD(sctp_stream_change_event, strchange_outstrms, 14);
SIZE(sctp_pdapi_event, 24);
FIELD(sctp_pdapi_event, pdapi_indication, 8);
FIELD(sctp_pdapi_event, pdapi_assoc_id, 12);
FIELD(sctp_pdapi_event, pdapi_stream, 16);
FIELD(sctp_pdapi_event, pdapi_seq, 20);

int main(void) {
    puts("Linux N2 lifecycle UAPI assertions completed");
    return 0;
}
