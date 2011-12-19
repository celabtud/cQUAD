// cQUAD v0.1
// final revision October 20th, 2010
// by S. Arash Ostadzadeh
// ostadzadeh@gmail.com


// Initial attempt to reveal the pattern of channel data communication between a pair of cooperating functions
// some overview statistic are now written on console
// the depth of the trie levels has been increased from 8 to 16 for 64-bit full tracing
// The total number of Time Slices in now recorded in a filename with the name <Producer>_<Consumer>_dcc_profile_over.txt

// revision v0.1: initial attempt to remove the postprocessing phase.

#include "pin.H"
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <string>
#include <stack>

#ifdef WIN32
#define DELIMITER_CHAR '\\'
#else 
#define DELIMITER_CHAR '/'
#endif

struct trieNode {
    struct trieNode * list[16];
} *trieRoot=NULL;

struct AddressSplitter
{
    unsigned int h0:4;
    unsigned int h1:4;
    unsigned int h2:4;
    unsigned int h3:4;
    unsigned int h4:4;
    unsigned int h5:4;
    unsigned int h6:4;
    unsigned int h7:4;
    unsigned int h8:4;
    unsigned int h9:4;
    unsigned int h10:4;
    unsigned int h11:4;
    unsigned int h12:4;
    unsigned int h13:4;
    unsigned int h14:4;
    unsigned int h15:4;
    
};

// structure definition to keep track of producer->consumer Bindings! (number of bytes, the memory addresses used for exchange ...)
typedef struct 
 {
	unsigned char producer_no; // the id of the latest producer for this memory location
	unsigned long long int TS;  // the time stamp of the last write to this memory location
	unsigned long long int PSN; // Production Sequence Number
	unsigned long long int CSN; // Consumption Sequence Number
} Bucket;



// contains the routine to dump data into flat profile
#include "flatprofile.cpp"


/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

   char main_image_name[100];
   string producer,consumer;


   stack <string> CallStack; // our own virtual Call Stack to trace function call

   unsigned long long int Total_Ins=0,Total_Ins_TMP=0;  // just for counting the total number of executed instructions
   unsigned int Total_M_Ins=0; // total number of instructions but divided by a million

   BOOL Include_External_Images=FALSE; // a flag showing our interest to trace functions which are not included in the main image file

   BOOL Uncommon_Functions_Filter=TRUE;
   BOOL No_Stack_Flag = TRUE;   // a flag showing our interest to include or exclude stack memory accesses in analysis. The default value indicates tracing also the stack accesses. Can be modified by 'ignore_stack_access' command line switch
   BOOL Verbose_ON = FALSE;  // a flag showing the interest to print something when the tool is running or not!
   
			
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobProducer(KNOB_MODE_WRITEONCE, "pintool","p","", "Specify the producer function");

KNOB<string> KnobConsumer(KNOB_MODE_WRITEONCE, "pintool","c","", "Specify the consumer function");

KNOB<BOOL> KnobIgnoreStackAccess(KNOB_MODE_WRITEONCE, "pintool",
    "ignore_stack_access","1", "Ignore memory accesses within application's stack region");

KNOB<BOOL> KnobIgnoreUncommonFNames(KNOB_MODE_WRITEONCE, "pintool",
    "filter_uncommon_functions","1", "Filter out uncommon function names which are unlikely to be defined by user (beginning with question mark, underscore(s), etc.)");

KNOB<BOOL> KnobIncludeExternalImages(KNOB_MODE_WRITEONCE, "pintool",
    "include_external_images","0", "Trace functions that are contained in external image file(s)");

KNOB<BOOL> KnobVerbose_ON(KNOB_MODE_WRITEONCE, "pintool",
    "verbose","0", "Print information on the console during application execution");

    
/* ============T R A C I N G===================================== */
int RecordMemoryAccess(void * addy, bool writeFlag)
{
    int currentLevel=0;
    int i;
    struct trieNode* currentLP;
    struct AddressSplitter* ASP= (struct AddressSplitter *)&addy;
    
    unsigned int addressArray[16];
    
    addressArray[0]=ASP->h15;
    addressArray[1]=ASP->h14;
    addressArray[2]=ASP->h13;
    addressArray[3]=ASP->h12;
    addressArray[4]=ASP->h11;
    addressArray[5]=ASP->h10;
    addressArray[6]=ASP->h9;
    addressArray[7]=ASP->h8;
    addressArray[8]=ASP->h7;
    addressArray[9]=ASP->h6;
    addressArray[10]=ASP->h5;
    addressArray[11]=ASP->h4;
    addressArray[12]=ASP->h3;
    addressArray[13]=ASP->h2;
    addressArray[14]=ASP->h1;
    addressArray[15]=ASP->h0;

    
    if(!trieRoot)  /* create the first level in trie */
    {
            if(!(trieRoot=(struct trieNode*)malloc(sizeof(struct trieNode)) ) ) return 1; /* memory allocation failed*/
            else
                       for (i=0;i<16;i++) 
                              trieRoot->list[i]=NULL;
    }
            
    currentLP=trieRoot;                
    while(currentLevel<15)  /* proceed to the last level */
    {
        if(! (currentLP->list[addressArray[currentLevel]]) ) /* create new level on demand */
          {
            if(!(currentLP->list[addressArray[currentLevel]]=(struct trieNode*)malloc(sizeof(struct trieNode))) ) return 1; /* memory allocation failed*/
            else
                       for (i=0;i<16;i++) 
                              (currentLP->list[addressArray[currentLevel]])->list[i]=NULL;
          }
        
        currentLP=currentLP->list[addressArray[currentLevel]];
        currentLevel++;
    }            
    
    if(!currentLP->list[addressArray[currentLevel]]) /* create new bucket to store last function's access to this memory location */
    {
        if(!(currentLP->list[addressArray[currentLevel]]=(struct trieNode*)malloc(sizeof(Bucket)) ) ) return 1; /* memory allocation failed*/
        else 
        {
          ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> producer_no=0; /* still we are not sure about the producer! will decide later! */
          ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> PSN=0; 
          ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> CSN=0; 
        }
          
    }           
    if (writeFlag) // write access detected
    	{
	      string p=CallStack.top();
		  if (p!=producer) // this is not the produer we are looking for
          	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> producer_no=0; /* data stalled!  */
		  
		  else  // yes this is our producer!
		  {	  
          	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> producer_no=1; /* for now we only have one producer, so the id is either zero or one */
          	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> PSN++; 	// increase the producer sequence number
          	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> TS=Total_Ins; // record the time slice of the production
          }// end of else
    	}//
        
    else // read access detected
    	{
          if ( ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> producer_no) // last production for this address was from our producer!!
           {
          	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> CSN++; // increase the consumer sequence number
	        
	        //augment the profile file
	        if (Append_to_flat_profile
	        (
	           ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> TS,
        	   Total_Ins,
        	   ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> PSN,
        	   ((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> CSN,
        	   (unsigned long long int)addy 
        	))
   			    cerr << "\nError in updating the flat profile..." << endl;

	        
	        // for direct dump into flat profile, use the code below
        	//fprintf(flatprofile,"%lld %lld %lld %lld %llX\n",
        	//	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> TS,
        	//	Total_Ins,
        	//	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> PSN,
        	//	((Bucket*) (currentLP->list[addressArray[currentLevel]]) )-> CSN,
        	//	(unsigned long long int)addy );
 		  }
    	} // end of the read access

    return 0; /* successful trace */
}

/* ===================================================================== */
VOID EnterFC(char *name,bool flag) 
{

  // revise the following in case you want to exclude some unwanted functions under Windows and/or Linux

  if (!flag) return;   // not found in the main image, so skip the current function name update

#ifdef WIN32

  if (Uncommon_Functions_Filter)

	if(		
		name[0]=='_' ||
		name[0]=='?' ||
		!strcmp(name,"GetPdbDll") || 
	    	!strcmp(name,"DebuggerRuntime") || 
	    	!strcmp(name,"atexit") || 
	    	!strcmp(name,"failwithmessage") ||
		!strcmp(name,"pre_c_init") ||
		!strcmp(name,"pre_cpp_init") ||
		!strcmp(name,"mainCRTStartup") ||
		!strcmp(name,"NtCurrentTeb") ||
		!strcmp(name,"check_managed_app") ||
		!strcmp(name,"DebuggerKnownHandle") ||
		!strcmp(name,"DebuggerProbe") ||
		!strcmp(name,"failwithmessage") ||
		!strcmp(name,"unnamedImageEntryPoint")
	   ) return;
#else
  if (Uncommon_Functions_Filter)

	if( name[0]=='_' || name[0]=='?' || 
            !strcmp(name,"call_gmon_start") || !strcmp(name,"frame_dummy") 
          ) return;
#endif
    

	// update the current function name	 
	string RName(name);
	CallStack.push(RName);
}


VOID EnterFC_EXTERNAL_OK(char *name) 
{

  // revise the following in case you want to exclude some unwanted functions under Windows and/or Linux

#ifdef WIN32

  if (Uncommon_Functions_Filter)

	if(		
		name[0]=='_' ||
		name[0]=='?' ||
		!strcmp(name,"GetPdbDll") || 
	    	!strcmp(name,"DebuggerRuntime") || 
	    	!strcmp(name,"atexit") || 
	    	!strcmp(name,"failwithmessage") ||
		!strcmp(name,"pre_c_init") ||
		!strcmp(name,"pre_cpp_init") ||
		!strcmp(name,"mainCRTStartup") ||
		!strcmp(name,"NtCurrentTeb") ||
		!strcmp(name,"check_managed_app") ||
		!strcmp(name,"DebuggerKnownHandle") ||
		!strcmp(name,"DebuggerProbe") ||
		!strcmp(name,"failwithmessage") ||
		!strcmp(name,"unnamedImageEntryPoint")
	   ) return;
#else
  if (Uncommon_Functions_Filter)

	if( name[0]=='_' || name[0]=='?' || 
            !strcmp(name,"call_gmon_start") || !strcmp(name,"frame_dummy") 
          ) return;
#endif
    

	// update the current function name	 
	string RName(name);
	CallStack.push(RName);
}

/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "\ncQUAD (Data Communication Channel Profiler) v0.1\nThis tool reveals the pattern of the data communication between any pair of functions in a program. The information extracted is used in modeling the behaviour of the data communication channel between the functions.\n\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}


/* ===================================================================== */


VOID  Return(VOID *ip)
{
       string fn_name = RTN_FindNameByAddress((ADDRINT)ip);


       if(!(CallStack.empty()) && (CallStack.top()==fn_name))
	   {  
		   CallStack.pop();
	   }
			
}

/* ===================================================================== */

VOID UpdateCurrentFunctionName(RTN rtn,VOID *v)
{
	  
	bool flag;
	char *s=new char[120];
	string RName;
	
		
	RName=RTN_Name(rtn);
	strcpy(s,RName.c_str());
	RTN_Open(rtn);
            
        // Insert a call at the entry point of a routine to push the current routine to Call Stack
        
	if (!Include_External_Images)  // I need to know whether or not the function is in the main image
	{
	      flag=(!((IMG_Name(SEC_Img(RTN_Sec(rtn))).find(main_image_name)) == string::npos));
	      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)EnterFC, IARG_PTR, s, IARG_BOOL, flag, IARG_END);    
	}
	else
	      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)EnterFC_EXTERNAL_OK, IARG_PTR, s, IARG_END);    
	

        // Insert a call at the exit point of a routine to pop the current routine from Call Stack if we have the routine on the top
	// RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)exitFc, IARG_PTR, RName.c_str(), IARG_END);
        
	RTN_Close(rtn);
	
}
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	// trigger to flush the last record in the flat profile buffer
	if (Append_to_flat_profile(0,0,0,0,0)) // dummy values 
			    cerr << "\nError in updating the flat profile..." << endl;

    cerr << "\nFinished executing the instrumented application..." << endl;
    fclose(flatprofile);    
    cerr << "done!" << endl;
    cerr << "Total number of time slices = "<< Total_Ins << endl;
    cerr << "Address Range = "<< "[ 0x " << hex << uppercase << setfill('0') << setw(16) << Min_addy 
    	 << " - 0x " << hex << uppercase << setfill('0') << setw(16) << Max_addy <<" ]" << endl;
    
    
    // update the overview file
    fprintf(overprofile,"%lld\n",Total_Ins); // total instructions (time slices)
    fprintf(overprofile,"0x%llX\n",Min_addy); // The low boundary of the accessed memory addresses
    fprintf(overprofile,"0x%llX\n",Max_addy); // The high boundary of the accessed memory addresses

    fclose(overprofile);
}



static VOID RecordMem(VOID * ip, CHAR r, VOID * addr, INT32 size, BOOL isPrefetch)
{

	if(!isPrefetch) // if this is not a prefetch memory access instruction  
	{
	   string temp=CallStack.top();
	   if ( r=='R' && temp!=consumer  ) return;  // function not related to consumer in read!

       for(int i=0;i<size;i++)
	    {
			RecordMemoryAccess(addr,r=='W');
			addr=((char *)addr)+1;  // cast not needed anyway!
	   	
	    	if (Verbose_ON && Total_Ins_TMP>999999)
	    	{
	      		Total_M_Ins++;
	      		cout<<(char)(13)<<"                                                                   ";
	      		cout<<(char)(13)<<"Instructions executed so far = "<<Total_M_Ins<<" M";
	      		Total_Ins_TMP=0;
	    	}
        }

       }// end of not a prefetch
}


static VOID RecordMemSP(VOID * ip, VOID * ESP, CHAR r, VOID * addr, INT32 size, BOOL isPrefetch)
{

	if(!isPrefetch) // if this is not a prefetch memory access instruction  
	{
	   if (addr >= ESP) return;  // if we are reading from the stack range, ignore this access
        
	   string temp=CallStack.top();
	   if ( r=='R' && temp!=consumer  ) return;  // function not related to consumer in read!

       for(int i=0;i<size;i++)
	    {
			RecordMemoryAccess(addr,r=='W');
			addr=((char *)addr)+1;  // cast not needed anyway!
	   	
	    	if (Verbose_ON && Total_Ins_TMP>999999)
	    	{
	      		Total_M_Ins++;
	      		cout<<(char)(13)<<"                                                                   ";
	      		cout<<(char)(13)<<"Instructions executed so far = "<<Total_M_Ins<<" M";
	      		Total_Ins_TMP=0;
	    	}
        }

       }// end of not a prefetch

}

// increment routine for the total instruction counter
VOID IncreaseTotalInstCounter()
{
	Total_Ins++;
	Total_Ins_TMP++; // just for the verbose option

}

// Is called for every instruction and instruments reads and writes and the Ret instruction
VOID Instruction(INS ins, VOID *v)
{
	
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)IncreaseTotalInstCounter, IARG_END);
	
     if (INS_IsRet(ins))  // we are monitoring the 'ret' instructions since we need to know when we are leaving functions in order to update our own virtual 'Call Stack'. The mechanism to inject instrumentation code to update the Call Stack (pop) upon leave is not implemented directly contrary to the dive in mechanism. Could be a point for further improvement?! ...
     {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Return, IARG_INST_PTR, IARG_END);
     }
  
 if (!No_Stack_Flag)
  {
     if (INS_IsMemoryRead(ins) || INS_IsStackRead(ins) )
     {
        INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_UINT32, INS_IsPrefetch(ins),
                IARG_END);
     }

     if (INS_HasMemoryRead2(ins))
     {
         INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_UINT32, INS_IsPrefetch(ins),
                IARG_END);
     }

     if (INS_IsMemoryWrite(ins) || INS_IsStackWrite(ins) ) 
     {
         INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMem,
                IARG_INST_PTR,
                IARG_UINT32, 'W',
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_UINT32, INS_IsPrefetch(ins),
                IARG_END);
      }
    } // end of Stack is ok!
 
 else  // ignore stack access
  {
     if (INS_IsMemoryRead(ins) )
     {
        INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemSP,
                IARG_INST_PTR,
		IARG_REG_VALUE, REG_STACK_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_UINT32, INS_IsPrefetch(ins),
                IARG_END);
     }

     if (INS_HasMemoryRead2(ins))
     {
         INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemSP,
                IARG_INST_PTR,
		IARG_REG_VALUE, REG_STACK_PTR,
                IARG_UINT32, 'R',
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_UINT32, INS_IsPrefetch(ins),
                IARG_END);
     }

     if (INS_IsMemoryWrite(ins)) 
     {
         INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemSP,
                IARG_INST_PTR,
		IARG_REG_VALUE, REG_STACK_PTR,
                IARG_UINT32, 'W',
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_UINT32, INS_IsPrefetch(ins),
                IARG_END);
      }
  
  } // end of ignore stack 
   
}

/* ===================================================================== */

const char * StripPath(const char * path)
{
    const char * file = strrchr(path,DELIMITER_CHAR);
    if (file)
        return file+1;
    else
        return path;
}
/* ===================================================================== */

int  main(int argc, char *argv[])
{
    cerr << endl << "Initializing cQUAD..." << endl;
    char temp[100];
    
   // assume Out_of_the_main_function_scope as the first routine
   CallStack.push("Out_of_the_main_function_scope");


    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    No_Stack_Flag=KnobIgnoreStackAccess.Value(); // Stack access ok or not?
    producer=KnobProducer.Value(); // this is the producer function
    consumer=KnobConsumer.Value(); // this is the consumer function
    Uncommon_Functions_Filter=KnobIgnoreUncommonFNames.Value(); // interested in uncommon function names or not?
    Include_External_Images=KnobIncludeExternalImages.Value(); // include/exclude external image files?
    Verbose_ON=KnobVerbose_ON.Value();  // print something or not during execution
   

	if (producer=="")
	{
		cerr<<"\nCan not find the producer function name. Use '-p' to specify the producer function.\n";
		return 1;
	}
	
	if (consumer=="")
	{
		cerr<<"\nCan not find the consumer function name. Use '-c' to specify the consumer function.\n";
		return 1;
	}
	
    // parse the command line arguments for the main image name
    for (int i=1;i<argc-1;i++)
    {
	if (!strcmp(argv[i],"--")) 
	    {
	      strcpy(temp,argv[i+1]);
	      break;
	    }   
    }
    
    string fp_name=producer+"_"+consumer+"_dcc_profile.txt";
    flatprofile=fopen(fp_name.c_str(),"wt");
    if (!flatprofile)
       {
           cerr << "\nCan not create the profile file ... Aborting! " << endl;         
           return 1;
       }
    
    fp_name=producer+"_"+consumer+"_dcc_profile_over.txt";
    overprofile=fopen(fp_name.c_str(),"wt");

    if (!overprofile)
       {
           cerr << "\nCan not create the overview file ... Aborting! " << endl;         
           return 1;
       }


    strcpy(main_image_name,StripPath(temp));

	// register the instrumentation routines 
    RTN_AddInstrumentFunction(UpdateCurrentFunctionName,0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    cerr << "Starting the application to be analysed..." << endl;
    PIN_StartProgram();
   
    return 0;
}
