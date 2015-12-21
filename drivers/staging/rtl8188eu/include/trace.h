/* <license> */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rtl8188eu

#if !defined(_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_H_

#include <linux/tracepoint.h>

TRACE_EVENT(read8,
	    TP_PROTO(u32 addr, u8 data),
	    TP_ARGS(addr, data),
	    TP_STRUCT__entry(
		    __field(u32, addr)
		    __field(u8, data)
	    ),
	    TP_fast_assign(
		    __entry->addr = addr;
		    __entry->data = data;
	    ),
	    TP_printk("read8(%04x) = 0x%04x", __entry->addr, __entry->data)
);

TRACE_EVENT(read16,
	    TP_PROTO(u32 addr, u16 data),
	    TP_ARGS(addr, data),
	    TP_STRUCT__entry(
		    __field(u32, addr)
		    __field(u16, data)
	    ),
	    TP_fast_assign(
		    __entry->addr = addr;
		    __entry->data = data;
	    ),
	    TP_printk("read16(%04x) = 0x%04x", __entry->addr, __entry->data)
);

TRACE_EVENT(read32,
	    TP_PROTO(u32 addr, u32 data),
	    TP_ARGS(addr, data),
	    TP_STRUCT__entry(
		    __field(u32, addr)
		    __field(u32, data)
	    ),
	    TP_fast_assign(
		    __entry->addr = addr;
		    __entry->data = data;
	    ),
	    TP_printk("read32(%04x) = 0x%04x", __entry->addr, __entry->data)
);

#endif /* _TRACE_H_ */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
