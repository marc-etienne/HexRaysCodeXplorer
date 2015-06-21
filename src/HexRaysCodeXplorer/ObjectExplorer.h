/*	Copyright (c) 2013-2015
	REhints <info@rehints.com>
	All rights reserved.
	
	==============================================================================
	
	This file is part of HexRaysCodeXplorer

 	HexRaysCodeXplorer is free software: you can redistribute it and/or modify it
 	under the terms of the GNU General Public License as published by
 	the Free Software Foundation, either version 3 of the License, or
 	(at your option) any later version.

 	This program is distributed in the hope that it will be useful, but
 	WITHOUT ANY WARRANTY; without even the implied warranty of
 	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 	General Public License for more details.

 	You should have received a copy of the GNU General Public License
 	along with this program.  If not, see <http://www.gnu.org/licenses/>.

	==============================================================================
*/

#pragma once

#include "ida.hpp"
#include "netnode.hpp"
#include <kernwin.hpp>
#include <stdint.h>

#include <windows.h>


// Object Explorer From Init
struct object_explorer_info_t
{
	TForm *form;
	TCustomControl *cv;
	TCustomControl *codeview;
	strvec_t sv;
	object_explorer_info_t(TForm *f) : form(f), cv(NULL) {}
};

void object_explorer_form_init();


// VTBL 
struct VTBL_info_t
{
	qstring vtbl_name;
	ea_t ea_begin;
	ea_t ea_end;
	uint32_t methods;
	
};


extern qvector <qstring> vtbl_list;
extern qvector <qstring>::iterator vtbl_iter;


bool get_vtbl_info(ea_t ea_address, VTBL_info_t &vtbl_info);
inline bool is_valid_name(char * name){ return(*((uint32_t*) name) == 0x375F3F3F /*"??_7"*/); }
void parse_vft_members(char * name, ea_t ea_start, ea_t ea_end);

void search_objects(bool bForce = true);


template <class T> bool verify_32_t(ea_t ea_ptr, T &rvalue)
{
	if(getFlags(ea_ptr))
	{
		rvalue = (T) get_32bit(ea_ptr);
		return(true);
	}

	return(false);
}


// RTTI
struct RTTI_info_t
{
	void * vftable;
	void * m_data;
	char  m_d_name[MAXSTR]; // mangled name (prefix: .?AV=classes, .?AU=structs)
};

static bool is_valid_rtti(RTTI_info_t *pIDA);
static char ** get_name(RTTI_info_t *pIDA, char ** pszBufer, int iSize);

// returns true if mangled name is a unknown type name
static inline bool is_type_name(char * pszName){ return((*((uint32_t*)pszName) & 0xFFFFFF) == 0x413F2E /*".?A"*/); }


struct PMD
{
	int mdisp;	// member
	int pdisp;  // vftable
	int vdisp;  // place inside vftable		
};


struct RTTIBaseClassDescriptor
{
	RTTI_info_t *pTypeDescriptor;	// type descriptor of the class
	uint32_t numContainedBases;			// number of nested classes
	PMD  pmd;						// pointer-to-member displacement info
	uint32_t attributes;				// flags (usually 0)
};


struct RTTIClassHierarchyDescriptor
{
	uint32_t signature;			// always zero?
	uint32_t attributes;		// bit 0 set = multiple inheritance, bit 1 set = virtual inheritance
	uint32_t numBaseClasses;	// number of classes in pBaseClassArray
	RTTIBaseClassDescriptor **pBaseClassArray;
};

const uint32_t CHDF_MULTIPLE = (1 << 0);
const uint32_t CHDF_VIRTUAL = (1 << 1);


struct RTTICompleteObjectLocator
{
	uint32_t signature;					// always zero ?
	uint32_t offset;					// offset of this vftable in the complete class
	uint32_t cdOffset;					// constructor displacement offset
	RTTI_info_t *pTypeDescriptor;	// TypeDescriptor of the complete class
	RTTIClassHierarchyDescriptor *pClassDescriptor; // 10 Describes inheritance hierarchy
};

ea_t find_RTTI(ea_t start_ea, ea_t end_ea);
char* get_demangle_name(ea_t class_addr);
void process_rtti();

char * get_text_disasm(ea_t ea);

bool get_vbtbl_by_ea(ea_t vtbl_addr, VTBL_info_t &vtbl);

tid_t create_vtbl_struct(ea_t vtbl_addr, ea_t vtbl_addr_end, char* vtbl_name, uval_t idx, unsigned int* vtbl_len = NULL);