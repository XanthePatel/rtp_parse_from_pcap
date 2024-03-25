#ifndef __COMMON_DEFINE__
#define __COMMON_DEFINE__


#define __LITTLE_ENDIAN_BITFIELD

/* rtsp interleaved frame header struct */
typedef struct
{
    unsigned int magic : 8;     // $
    unsigned int channel : 8;   //0-1
    unsigned int rtp_len : 16;
}rtsp_interleaved_frame_hdr;


/*
 *
 *
 *    The RTP header has the following format:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           timestamp                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           synchronization source (SSRC) identifier            |
 * +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 * |            contributing source (CSRC) identifiers             |
 * |                             ....                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * RTP data header
 */

#define DISABLE_DAV_FILE

typedef struct {
#if defined(__BIG_ENDIAN_BITFIELD)
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int x:1;         /* header extension flag */
    unsigned int cc:4;        /* CSRC count */
    unsigned int m:1;         /* marker bit */
    unsigned int pt:7;        /* payload type */
#elif defined (__LITTLE_ENDIAN_BITFIELD)
    unsigned int cc:4;        /* CSRC count */
    unsigned int x:1;         /* header extension flag */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
    unsigned int pt:7;        /* payload type */
    unsigned int m:1;         /* marker bit */
#else
#error  "Please choose endian"
#endif

    unsigned int seq:16;      /* sequence number */
    unsigned int ts;               /* timestamp */
    unsigned int ssrc;             /* synchronization source */
} rtp_hdr_t;

#define TOTAL_HEAD_LEN (sizeof(rtsp_interleaved_frame_hdr) + sizeof(rtp_hdr_t))

#define RTP_HEAD_LEN (sizeof(rtp_hdr_t))










#endif