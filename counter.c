//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


//kita gunanakan 'map_type_array' karena map ini bentipe index , setiap entry akan diindex
	//sehingga akan mundah untuk retrieve data
//max_entrie bernilai seperti itu karena kita hanya tracking one value dari tiap entry atau packet yg data
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps"); 

// section 'xdp' ini menyakan bahwa fungsi ini adalah 'xdp program', sehingga program ini akan diattach ke network interfaces
	//to process packet yg datang 
// key 
	//zero value -> karen array dengan single entry, sehingga akan selalu zero
// *count
	//karena nilai akan akan selalu berubah atau dynamic , maka digunakna pointer
	//'bpf_map_lookup_elem' 
		//adalah helper function yg digunakan untuk interacrt dengan maps 'pkt_count'
		//fungsi ini kana mencari 'value' berdasar 'key' pada map ,retrieve value ,dan di stoure pada *count
		//Returns zero on success, and -one on failure 
	//__sync_fetch_and_add
		//atomic operation , jika ada multiple packet , update dilakukan atomical
		//jika ada packet datang bersamaan tidak dihitung satu , tapi tetap dihitung dua packet
	// XDP_PASS
		// packer yg telahd diprocess passing ke tahap selanjutnya
SEC("xdp") 
int count_packets() {
    __u32 key    = 0;     
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key); 
    if (count) { 
        __sync_fetch_and_add(count, 1); 
    }

    return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL";
