/*
 * IDA 7.0 script that exports functions and global variables from a project
 *
 * The types are not exported, as they come from a header file that can be
 * imported/exported using features officially supported in IDA.
 *
 * @author: Nicolas Iooss
 */
#include <idc.idc>

static main() {
    auto exported_file_path = get_input_file_path() + ".exported.idc";
    exported_file_path = AskFile(-1, exported_file_path, "Please choose the exported file");
    print("Exporting to " + exported_file_path);

    auto fhandle = fopen(exported_file_path, "wb");
    if(fhandle == 0) {
        print("Error opening output file");
        return -1;
    }
    writestr(fhandle, "// Export of " + get_root_filename() + "\n");
    writestr(fhandle, "// Import this in IDA 7.0+ using IDC and after importing structures.h\n");
    writestr(fhandle, "#include <idc.idc>\n");
    writestr(fhandle, "static main() {\n");

    auto funcea = get_first_seg();
    while (funcea != BADADDR) {
        auto func_name = get_func_name(funcea);
        auto func_type = get_type(funcea);

        if (substr(func_name, 0, 4) != "sub_") {
            writestr(fhandle, sprintf("    set_name(%#x, \"%s\");\n", funcea, func_name));
            if (func_type != "") {
                // Patch the type in a very dirty way in order to include a function name
                // No thanks to IDA developers who made SetType/apply_type NOT a mirror for get_type() :(
                auto paren_pos = strstr(func_type, "(");
                if (paren_pos != -1) {
                    // with "__usercall@<al>", the name needs to be inserted before the "@"
                    auto arobas_pos = strstr(substr(func_type, 0, paren_pos), "@");
                    if (arobas_pos != -1) {
                        paren_pos = arobas_pos;
                    }
                    func_type = substr(func_type, 0, paren_pos) + " x" + substr(func_type, paren_pos, -1);
                }
                writestr(fhandle, sprintf("    SetType(%#x, \"%s\");\n", funcea, func_type));
            }
        }

        funcea = get_next_func(funcea);
    }
    writestr(fhandle, "    print(\"Import OK :)\");\n");
    writestr(fhandle, "    return 0;\n");
    writestr(fhandle, "}\n");
    fclose(fhandle);
    print("Done.");
    return 0;
}
