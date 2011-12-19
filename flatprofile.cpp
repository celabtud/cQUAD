// This module only contains the routine to augment the flat profile during the execution of the instrumentated application
// Bindings are appended to the end of the flat profile as they happen during execution

// Global Variables
FILE *flatprofile, *overprofile;
unsigned long long int Min_addy=0xFFFFFFFFFFFFFFFF, Max_addy=0; // keep the boundaries of accessed memory addresses


int Append_to_flat_profile
  (
	unsigned long long int current_PTS,
	unsigned long long int current_CTS,
	unsigned long long int current_PSN,
	unsigned long long int current_CSN,
	unsigned long long int current_addy
  )

{

// necessary variables to keep the starting byte info for a data item accessed in continuous memory accesses.
// It should be noted that for accessing a data item with the size of more than 1 byte, the tracing generates 8 continous calls to the following function.
// The function keeps the trace and only writes the event on the completion of all the partial access records.
	static unsigned long long int start_PTS=current_PTS;
	static unsigned long long int start_CTS=current_CTS;
	static unsigned long long int start_PSN=current_PSN;
	static unsigned long long int start_CSN=current_CSN;
	static unsigned long long int start_addy=current_addy;
	static unsigned char size=0;
	
	int returnvalue=0;

	if (!(start_PTS==current_PTS && start_CTS==current_CTS && start_PSN==current_PSN && start_CSN==current_CSN && start_addy==current_addy-size)) 
		// the current record is not the continuation of the previous access
		{
			if (start_addy<Min_addy) Min_addy=start_addy;
			if (start_addy>Max_addy) Max_addy=start_addy;
			
			// write the current record to the flat profile
			if (fprintf(flatprofile,"%lld %lld \n",start_PTS,start_CTS)<=0)
				returnvalue=1; 
			
			start_PTS=current_PTS;
			start_CTS=current_CTS;
			start_PSN=current_PSN;
			start_CSN=current_CSN;
			start_addy=current_addy;
			
			size=1;
		}
	else size++;

return returnvalue;
}
