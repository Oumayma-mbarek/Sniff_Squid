#include <stdio.h>
#include <stdlib.h>
#include "sniff_squid.h"
#include "dash/dash.h"

typedef struct arguments {
    char* verbosity;
    char* offline;
    char* interface;
    char* filter;
    bool help;
} Arguments;


int main(int argc, char* argv[])
{
    int return_code = EXIT_FAILURE;
    Arguments args;
    int verbosity = 1;
    // TODO: change descriptions
    dash_Longopt options[] = {
        {.user_pointer = &(args.help), .longopt_name = "help", .opt_name = 'h', .description = "Send help "},
        {.user_pointer = &(args.interface),
         .longopt_name = "interface",
         .opt_name     = 'i',
         .param_name   = "interface",
         .description  = "Listen on $ (if unset, trigger a prompt)"},
        {.user_pointer = &(args.filter), .longopt_name = "filter", .opt_name = 'f', .param_name = "filter", .description = "A pcap $ to only get some packets."},
        {.user_pointer = &(args.offline),
         .longopt_name = "offline",
         .opt_name     = 'o',
         .param_name   = "file",
         .description  = "An input $ that can be used instead of sniffing the network"},
        {.user_pointer = &(args.verbosity),
         .longopt_name = "verbosity",
         .opt_name     = 'v',
         .param_name   = "level",
         .description  = "Set the verbosity to $, authorized levels are 1, 2 or 3 (default: 3)"},
        {.user_pointer = NULL}
    };

    if(!dash_arg_parser(&argc, argv, options))
    {
        fputs("incorrect arguments\n", stderr);
        goto FREE;
    }

    if(args.help)
    {

        dash_print_usage(argv[0], "", "", NULL, options, stderr);
    }

    if(args.verbosity)
    {
        verbosity = atoi(args.verbosity);
        if(verbosity < 1 || verbosity > 3)
        {
            fprintf(stderr, "verbosity should take one of these values : 1,2 or 3\n");
            goto FREE;
        }
    }

    read_capture(verbosity, args.interface, args.filter, args.offline);

    return_code = EXIT_SUCCESS;
FREE:
    dash_free(options);
    return return_code;
}
