/*
 *      log-util.c
 *      
 *      Created on: 2011-04-03
 *      Author:     Hugo Caron
 *      Email:      <h.caron@codsec.com>
 * 
 * Copyright (C) 2011 by Hugo Caron
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "output-util.h"

#include <stdio.h>
#include <time.h>

FILE *fpLog = 0;

int openLog(char *filename){
	TRACE(L_DEBUG, "log: open file %s ...", filename);
	
	fpLog = fopen(filename, "a+");
	if ( fpLog == 0 ){
		perror("fopen");
		return -1;
	}

	return 0;
}

void closeLog(){
	if ( fpLog != 0 ){
		fclose(fpLog);
		TRACE(L_DEBUG, "log: close file");
	}
}

void writeLog(char *line){
	
	time_t tim=time(NULL);
    struct tm *now=localtime(&tim);	

	TRACE(L_NOTICE, "%d/%02d/%02d %02d:%02d:%02d | %s",
		now->tm_year+1900, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec,
		line);
	
	if ( fpLog != 0 ){
		TRACE(L_DEBUG, "log: write line");
		fprintf(fpLog, "%d/%02d/%02d %02d:%02d:%02d | %s\n", 
			now->tm_year+1900, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec,
			line);
	}
	
	fflush(fpLog);
}


