#include <stdlib.h>
#include <arpa/inet.h>

#include "rtp_parser.h"
#include <iostream>
using namespace std;

rtp_parser::stream_map rtp_parser::streams;
rtp_parser* rtp_parser::instance(unsigned int src_ip, unsigned short src_port, unsigned int dst_ip, unsigned short dst_port)
{
	multi_key key(src_ip, src_port, dst_ip, dst_port);
	stream_map::iterator it;

	it = streams.find(key);

	if( it == streams.end())
	{
		rtp_parser *new_stream = new rtp_parser(src_ip, src_port, dst_ip, dst_port);
		streams[key] = new_stream;
		return new_stream;
	}
	else
	{
		return it->second;
	}
}

rtp_parser::rtp_parser(unsigned int src_ip, unsigned short src_port, unsigned int dst_ip, unsigned short dst_port)
	: buffer(1024), 
	state(SEARCH_HDR), 
	rpt_pkt_len(0), 
	is_file_created(false), 
	dav_file(NULL), 
	parse_file(NULL),
	rtp_head_file(NULL),
	ps_head_file(NULL),
	is_first_frm(true),
	wait_frame(true),
	ssrc(0),
	fist_pkg(true),
	PaddingCount(0)
{
	buffer.kmp_init("$");
	//is_big_endian = check_big_endian();

	struct in_addr src;
	struct in_addr dst;

	char src_port_str[10];
	char dst_port_str[10];

	src.s_addr = src_ip;
	dst.s_addr = dst_ip;

	snprintf(src_port_str, sizeof(src_port_str), "%u", src_port);
	snprintf(dst_port_str, sizeof(dst_port_str), "%u", dst_port);
	
	dav_file_name =  "src[" + std::string(inet_ntoa(src)) + "[" + src_port_str + "]]--dst[" + std::string(inet_ntoa(dst)) + "[" + dst_port_str + "]].dav";
	parse_file_name =  "src[" + std::string(inet_ntoa(src)) + "[" + src_port_str + "]]--dst[" + std::string(inet_ntoa(dst)) + "[" + dst_port_str + "]].txt";
	rtp_head_file_name = "src[" + std::string(inet_ntoa(src)) + "[" + src_port_str + "]]--dst[" + std::string(inet_ntoa(dst)) + "[" + dst_port_str + "]].rtp";
	ps_head_file_name = "PS-src[" + std::string(inet_ntoa(src)) + "[" + src_port_str + "]]--dst[" + std::string(inet_ntoa(dst)) + "[" + dst_port_str + "]].txt";
}

rtp_parser::~rtp_parser()
{
	if (NULL != dav_file)
	{
		fclose(dav_file);
	}
	
	if (NULL != parse_file)
	{
		fclose(parse_file);
	}
}
void rtp_parser::put_data(const char *payload, unsigned int len, struct timeval *capture_time)
{
	buffer.write_data(payload, len);
	search_frame(capture_time);
	state = SEARCH_HDR;
	COMMON_LOG("-----------------------------------------new buffer state : %d",state);

}

void rtp_parser::search_frame(struct timeval *capture_time)
{
	int ret;
	bool frm_end = false;

	switch(state)
	{
		case SEARCH_HDR:
			rpt_pkt_len = buffer.parse_as_ushort(0);
			COMMON_LOG("rpt_pkt_len : %d",rpt_pkt_len);
			if (buffer.get_data_size() < rpt_pkt_len)
			{
				//buffer.drop_data(buffer.get_data_size());//drop all invalid data
				return;	//wait next packet
			}
			

			// if (buffer.get_data_size() - 2 != rpt_pkt_len)
			// {
			// 	//“RFC 4571 packet len”  not find
			// 	buffer.drop_data(buffer.get_data_size());//drop all invalid data
			// 	return;	//wait next packet
			// }

			// find head
			buffer.drop_data(2); // drop no use data, the frame head is in the front of buffer

			state = BUILD_HDR;
			if (!fist_pkg)
			{
				rtp_pkt_start_time = last_rtp_pkt_end_time;
			}
			else
			{
				rtp_pkt_start_time = *capture_time;
			}
			
			

			if (wait_frame)
			{
				frm_start_time = *capture_time;
				wait_frame = false;
			}
			// }
			
			break;
		case BUILD_HDR:
			if (buffer.get_data_size() < RTP_HEAD_LEN  ) // rtp包前有2个字节表示该rtp包的大小“RFC 4571 packet len”
			{
				COMMON_LOG("wait next packet, buffer.get_data_size() : %d",buffer.get_data_size());
				return;	//wait next packet
			}
			else
			{
				state = CHECK_HDR;			
			}
			
			break;
		case CHECK_HDR:

			//todo convert buffer to rtp_hdr_t struct
			cout << "----------------------------------------" << endl;

			COMMON_LOG("buffer.parse_as_char(0): %x",buffer.parse_as_char(0));
			COMMON_LOG("buffer.parse_as_char(1): %x",buffer.parse_as_char(1));
			COMMON_LOG("buffer.parse_as_char(2): %x",buffer.parse_as_char(2));
			COMMON_LOG("check_bit_value:%d %d %d %d %d %d %d %d", buffer.check_bit_value(0, 0), buffer.check_bit_value(0, 1), buffer.check_bit_value(0, 2), buffer.check_bit_value(0, 3), buffer.check_bit_value(0, 4), buffer.check_bit_value(0, 5), buffer.check_bit_value(0, 6), buffer.check_bit_value(0, 7));
			COMMON_LOG("buffer.parse_as_bits(2, 6, 7): %d",buffer.parse_as_bits(0, 6, 7));

			
			cout << "11111111111111111111111111111111111111111" << endl;

			if (ssrc == 0)
			{
				ssrc = buffer.parse_as_uint(8);
				COMMON_LOG("ssrc:%x", ssrc);
				COMMON_LOG("ssrc:%d", ssrc);
				COMMON_LOG("ssrc:%x  %x %x %x ", buffer.parse_as_char(0), buffer.parse_as_char(1), buffer.parse_as_char(2), buffer.parse_as_char(3));
				COMMON_LOG("ssrc:%x  %x %x %x ", buffer.parse_as_char(4), buffer.parse_as_char(5), buffer.parse_as_char(6), buffer.parse_as_char(7));
				COMMON_LOG("ssrc:%x  %x %x %x ", buffer.parse_as_char(8), buffer.parse_as_char(9), buffer.parse_as_char(10), buffer.parse_as_char(11));
				COMMON_LOG("ssrc:%x  %x %x %x ", buffer.parse_as_char(12), buffer.parse_as_char(13), buffer.parse_as_char(14), buffer.parse_as_char(15));
			}
			else if (ssrc != buffer.parse_as_uint(8))
			{
				buffer.drop_data(1);
				state = SEARCH_HDR;
				break;
			}


			// rpt_pkt_len = buffer.parse_as_ushort(0);
			state = BUILD_FRAME;			
			
			break;
		case BUILD_FRAME:
			if (buffer.get_data_size() < rpt_pkt_len)//此处应该再加上一个判断当buffer.get_data_size() > rpt_pkt_len 的情况，进行分包读取处理
			{
				return; //wait the frame to be completed
			}
			else
			{// whole frame arrive
				
				rtp_pkt_end_time = *capture_time;
				if (!is_file_created)
				{
#ifndef DISABLE_DAV_FILE
					dav_file = fopen(dav_file_name.c_str(), "wb");
					if ( dav_file == NULL )
					{
						COMMON_LOG("create file[%s] failed!",dav_file_name.c_str());
						exit(1);
					}
#endif
					parse_file = fopen(parse_file_name.c_str(), "wb");
					if ( parse_file == NULL )
					{
						COMMON_LOG("create file[%s] failed!",parse_file_name.c_str());
						exit(1);
					}

					rtp_head_file = fopen(rtp_head_file_name.c_str(), "wb");
					if ( rtp_head_file == NULL )
					{
						COMMON_LOG("create file[%s] failed!",rtp_head_file_name.c_str());
						exit(1);
					}

					is_file_created = true;
				}

				// we must write frame info before writing this frame to file ,
				// because write_to_file will drop this frame.
				COMMON_LOG("check_bit_value check marker :%d %d %d %d %d %d %d %d", buffer.check_bit_value(1, 0), buffer.check_bit_value(1, 1), buffer.check_bit_value(1, 2), buffer.check_bit_value(1, 3), buffer.check_bit_value(1, 4), buffer.check_bit_value(1, 5), buffer.check_bit_value(1, 6), buffer.check_bit_value(1, 7));
				if (buffer.check_bit_value(1, 7))   /* check if the last rtp packet of current frame(MAKER bit) */
				{
					frm_end_time = *capture_time;
					wait_frame = true;
					frm_end = true;
					// exit(-1);
				}
				
				write_frm_info();

				write_rtp_head();

				last_rtp_pkt_end_time = rtp_pkt_end_time;
				fist_pkg = false;

				// exit(-1);

#ifndef DISABLE_DAV_FILE
				buffer.write_to_file(dav_file, rpt_pkt_len + sizeof(rtsp_interleaved_frame_hdr));
#else
				buffer.drop_data(rpt_pkt_len);//2字节为“RFC 4571 packet len”
#endif

				if (frm_end)
				{
					last_frm_end_time = *capture_time;
				}
				
				state = SEARCH_HDR;
			}	
			
			break;
		default:			
			COMMON_LOG("state %d error!", state); 
			return;
	}

	search_frame(capture_time); //check is there another rtp packet in memory
	return; 				
}

/*
bool rtp_parser::check_big_endian()
{ 
    union { 
        uint i; 
        char c[4]; 
    } bint = {0x01020304}; 
 
    return bint.c[0] == 1;  
}
*/

void rtp_parser::write_frm_info()
{
	fprintf(parse_file, "rtp seq:%8hu, Marker:%d, Len:%7u,   Begin_Rcv_Time:%10lu.%6lus,   End_Rcv_Time:%10lu.%6lus,  Cost_Time:%8uus \n", 
		buffer.parse_as_ushort(2), buffer.check_bit_value(1, 7), rpt_pkt_len, rtp_pkt_start_time.tv_sec, rtp_pkt_start_time.tv_usec, rtp_pkt_end_time.tv_sec, rtp_pkt_end_time.tv_usec, time_diff(&rtp_pkt_start_time, &rtp_pkt_end_time));

	if (buffer.check_bit_value(1, 7))
	{
		if (is_first_frm)
		{
			fprintf(parse_file, "\nFrame info: Begin_Rcv_Time:%10lu.%6lus,	 End_Rcv_Time:%10lu.%6lus,	Cost_Time:%8uus \n\n", 
				 frm_start_time.tv_sec, frm_start_time.tv_usec, frm_end_time.tv_sec, frm_end_time.tv_usec, time_diff(&frm_start_time, &frm_end_time));

			is_first_frm = false;
		}
		else
		{
			fprintf(parse_file, "\nFrame info: Begin_Rcv_Time:%10lu.%6lus,	 End_Rcv_Time:%10lu.%6lus,	Cost_Time:%8uus Frm_Interval:%8uus \n\n", 
				 frm_start_time.tv_sec, frm_start_time.tv_usec, frm_end_time.tv_sec, frm_end_time.tv_usec, time_diff(&frm_start_time, &frm_end_time), time_diff(&last_frm_end_time, &frm_end_time));
		
		}
			
	}
}

void rtp_parser::write_rtp_head()
{
	fprintf(rtp_head_file, "Version: %d, Padding: %d, Extension: %d, CSRCCount: %d,Marker: %d, PayloadType: %d, SequenceNumber: %d, Timestamp: %d, SSRC: %d",
			buffer.parse_as_bits(0, 6, 7), buffer.check_bit_value(0, 5), buffer.check_bit_value(0, 4), buffer.parse_as_bits(0, 0, 3), buffer.check_bit_value(1, 7), buffer.parse_as_bits(1, 0, 6),
			buffer.parse_as_ushort(2), buffer.parse_as_uint(4), buffer.parse_as_uint(8), 0);

	if (buffer.check_bit_value(0, 5))
	{
		PaddingCount = buffer.parse_as_char(rpt_pkt_len - 1);
		fprintf(rtp_head_file, ", PaddingCount: %d, Paddingdata: %d \n",PaddingCount, buffer.parse_as_uint(rpt_pkt_len - PaddingCount));
	}
	else
	{
		fprintf(rtp_head_file,", PaddingCount: %d \n", PaddingCount);
	}
}

void rtp_parser::write_ps_head()
{
}

unsigned int rtp_parser::time_diff(struct timeval *start, struct timeval *end)
{
	unsigned long long micro_seconds_of_start = start->tv_sec * 1000 * 1000 + start->tv_usec;
	unsigned long long micro_seconds_of_end = end->tv_sec * 1000 * 1000 + end->tv_usec;

	if (micro_seconds_of_end >= micro_seconds_of_start)
	{
		return micro_seconds_of_end - micro_seconds_of_start;
	}
	else
	{
		return micro_seconds_of_start - micro_seconds_of_end;
	}
}
