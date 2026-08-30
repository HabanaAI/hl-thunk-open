import sys, getopt, os
import datetime

def print_usage():
    print ("-c <base test configuration path> -p <parameters list. e.g. red_op=add,sub,min,max red_dt=downscale,upscale,int8,bf16,fp32>"
           "-o <output directory path>")

def get_arguments(argv):
    cfg_path = ""
    params_list = ""
    out_dir = ""
    missing_arguments = 3

    try:
        opts, args = getopt.getopt(argv,"c:p:o:",["cfg_path=", "params=", "out_dir="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-c", "--cfg_path"):
            cfg_path = arg
            missing_arguments -= 1
        elif opt in ("-p", "--params"):
            params_list = arg
            missing_arguments -= 1
        elif opt in ("-o", "--out_dir"):
            out_dir = arg
            missing_arguments -= 1
        else:
            print_usage()
            sys.exit(2)

    if (missing_arguments > 0):
        print ("Not enough arguments!!!")
        print_usage()
        sys.exit(2)

    return cfg_path, params_list, out_dir

def main(argv):
    base_cfg_file_path =""
    params_str = ""
    out_dir = ""
    params_dic = dict()
    params_ctr_dic = dict()
    params_num_dic = dict()
    base_cfg_lines = list()
    run_script = list()

    base_cfg_file_path, params_str, out_dir = get_arguments(argv)

    out_dir = os.path.abspath(os.path.expanduser(os.path.expandvars(out_dir))) + "/"

    params_list = params_str.split()
    for param_w_values in params_list:
        key_val_split = param_w_values.split('=')
        params_dic[key_val_split[0]] = key_val_split[1].split(",")
        params_ctr_dic[key_val_split[0]] = 0
        params_num_dic[key_val_split[0]] = len(params_dic[key_val_split[0]])


    with open(os.path.abspath(os.path.expanduser(os.path.expandvars(base_cfg_file_path))), "r") as f:
        org_cfg_lines = f.readlines()

    for line in org_cfg_lines:
        found_param = 0
        for key in params_dic.keys():
            if (line.startswith(key + '=')):
                found_param = 1
        if line.startswith(';') or not(found_param):
            base_cfg_lines.append(line)

    result_file_name = out_dir + os.path.basename(base_cfg_file_path).replace(".txt","_res.txt")

    keys_list = list(params_dic.keys())
    last_key = keys_list[-1]
    first_key = keys_list[0]
    keys_list_size = len(keys_list)
    test_num = 0

    # iterate on all parameters and create a test configuration file per combination
    while params_ctr_dic[first_key] < params_num_dic[first_key]:
        suffix = ""
        cfg_str = ""
        additional_lines = list()
        valid_str = 1
        for key in params_dic.keys():
            curr_index = keys_list.index(key)
            if curr_index < keys_list_size - 1:
                next_key = keys_list[curr_index + 1]
                if params_ctr_dic[next_key] == params_num_dic[next_key]:
                    params_ctr_dic[next_key] = 0
                    params_ctr_dic[key] += 1
                    if (params_ctr_dic[key] == params_num_dic[key]):
                        valid_str = 0
                        break
            suffix += "__" + key + "--" + params_dic[key][params_ctr_dic[key]]
            additional_lines.append(key + "=" + params_dic[key][params_ctr_dic[key]] + "\n")
            if last_key == key:
                params_ctr_dic[key] += 1
        if (valid_str):
            new_file_path = os.path.basename(base_cfg_file_path).replace(".txt", suffix + ".txt")
            with open(out_dir + new_file_path, "w") as f:
                f.write(''.join(base_cfg_lines + additional_lines))
            run_script.append("(echo;echo [" + str(test_num) + "\\\\#*#] start time: $(date); echo running " + new_file_path + ":) | tee -a " + result_file_name + "\n")
            run_script.append("sudo $BUILD_ROOT/hlthunk_release_build/bin/nic_root -s test_nic_e2e_lpbk -c " +  out_dir + new_file_path +" 2>&1 1>> " + result_file_name + " | sudo tee -a " + result_file_name +  "\n")
            test_num += 1


    run_all_file_name = out_dir + os.path.basename(base_cfg_file_path).replace(".txt","_run_all.sh")
    test_num -= 1
    with open(run_all_file_name, "w") as f:
        f.write("echo -n > " + result_file_name + "\n")
        f.write(''.join(run_script).replace("#*#",str(test_num)))
    os.chmod(run_all_file_name, 0o777)

    return 0

if __name__ == "__main__":
    main(sys.argv[1:])
