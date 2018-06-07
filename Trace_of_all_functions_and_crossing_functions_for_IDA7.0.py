# IDA Pro 7.0.170914 WIN\MAC x64 + Hex-Rays Decompilers (x86, x64, ARM, ARM64)
# May execute scripts for Python and .idc
# https://rutracker.org/forum/viewtopic.php?t=5459068

# After open .exe file in IDA (how to pe.dll):
# File->Script file...->'Select script'
# View->Recent scripts->'Press script enter'
# Window 'Output window' (down) move to main window

from idautils import *

Input_Functions = {
    'fgetc'    ,
    'fgets'    ,
    'fread'    ,
    'fscanf'   ,
    'getc'     ,
    'getchar'  ,
    'gets'     ,
    'read'     ,
    'read_chunk',
    'scanf'    ,
    'sscanf'   ,
    'vfscanf'  ,
    'vscanf'   ,
    'vsscanf'  ,
}

Unsafe_Functions = {
    'perror'   ,
    'vfprintf' ,
    'vprintf'  ,
    'atof'    ,
    'atoi'    ,
    'atol'    ,
    'memcpy'  ,
    'memmove' ,
    'memset'  ,
    'sprintf' ,
    'strcat'  ,
    'strcpy'  ,
    'strlen'  ,
    'strncpy' ,
    'fflush'  ,
}

g_list_of_traces_input_func = []
g_list_of_traces_unsafe_func = []

def Traceroute(function_name, lst=None):
    ea = ScreenEA()

    for function_ea in Functions(SegStart(ea), SegEnd(ea)):

        f_name = GetFunctionName(function_ea)
    
        # If function is trace function, for which was called Traceroute
        if function_name == f_name:

            if lst is None:
                
                lst = []

            # Add function in trace
            lst.append(GetFunctionName(function_ea))

            for ref_ea in CodeRefsTo(function_ea, 0):

                print '\t%s (0x%x) \t<-' % (f_name, function_ea)
                
                # If function isn't 'main' and isn't herself
                if (f_name.find('main') == -1) and (f_name.find(GetFunctionName(ref_ea)) == -1):
                
                    Traceroute(GetFunctionName(ref_ea), lst)
                
                    return


ea = ScreenEA()

for function_ea in Functions(SegStart(ea), SegEnd(ea)):

    f_name = GetFunctionName(function_ea)
    
    for it in Input_Functions:
        # If function is input function
        if it == f_name:

            print 'Trace of function %s at 0x%x' % (f_name, function_ea)

            # Get list all reference on function
            for ref_ea in CodeRefsTo(function_ea, 0):

                # Init list
                new_list = []

                # Add f_name in list
                new_list.append(f_name)

                Traceroute(GetFunctionName(ref_ea), new_list)

                # Add trace in global traces list input functions
                g_list_of_traces_input_func.append(new_list)

                print ' '

    for it in Unsafe_Functions:
        # If function is unsafe function
        if it == f_name:

            print 'Trace of function %s at 0x%x' % (f_name, function_ea)

            # Get list all reference on function
            for ref_ea in CodeRefsTo(function_ea, 0):

                # Init list
                new_list = []

                # Add f_name in list
                new_list.append(f_name)

                Traceroute(GetFunctionName(ref_ea), new_list)
                
                # Add trace in global traces list usafe functions
                g_list_of_traces_unsafe_func.append(new_list)

                print ' '


# Find crossing functions
for trace_unsafe_func in g_list_of_traces_unsafe_func:

    for it_from_trace_unsafe_func in trace_unsafe_func:
    
        for trace_input_func in g_list_of_traces_input_func:
    
            for it_from_trace_input_func in trace_input_func:
    
                if it_from_trace_input_func == it_from_trace_unsafe_func:
    
                    print 'Crossing function: %s' % it_from_trace_input_func
    
                    print '%s' % (trace_input_func[0]), trace_input_func
    
                    print '%s' % (trace_unsafe_func[0]), trace_unsafe_func
    
                    print ''
