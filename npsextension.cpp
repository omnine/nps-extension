/* Copyright (c) Microsoft Corporation. All rights reserved. */
#include "pch.h"

#include "windows.h"
#include "authif.h"
#include "lmcons.h"
#include "ntsecapi.h"
#include "radutil.h"

#include "loguru/loguru.hpp"

#include <sstream>
#include <map>
#include <string>
#include <iomanip>
#include <vector>

using namespace std;


/* The registry value where this extension is registered. */
LPCWSTR pwszDllType = AUTHSRV_EXTENSIONS_VALUE_W;

/* Global handle to the LSA. This is initialized once at start-up and reused
 * until shutdown. */
LSA_HANDLE hPolicy = NULL;

/*
extern "C" __declspec(dllexport)
DWORD
WINAPI
*/

STDAPI_(DWORD) RadiusExtensionInit( VOID )
{
   NTSTATUS status;
   LSA_OBJECT_ATTRIBUTES objectAttributes;

   memset(&objectAttributes, 0, sizeof(objectAttributes));
   status = LsaOpenPolicy(
               NULL,
               &objectAttributes,
               POLICY_LOOKUP_NAMES,
               &hPolicy
               );

   return LsaNtStatusToWinError(status);
}


STDAPI_(VOID) RadiusExtensionTerm( VOID )
{
   LsaClose(hPolicy);
   hPolicy = NULL;
}

map<string, vector<RADIUS_ATTRIBUTE*>> cacheMap;

vector<RADIUS_ATTRIBUTE*> CacheAttrs(PRADIUS_ATTRIBUTE_ARRAY pExisting) {
    //due to memory allocation and other reasons, we may not be able to do assign the pointer.
    // pExisting = pCached;
    // remove the existing items;
    DWORD size = pExisting->GetSize(pExisting);
    LOG_F(0, "Cache GetSize=(%d) Array length = (%d)",  size, pExisting->cbSize);

    vector<RADIUS_ATTRIBUTE*> vecAttrs;

    DWORD i = 0;
    while(i < size) {
        const RADIUS_ATTRIBUTE* pAttr = pExisting->AttributeAt(pExisting, i);
        i++;

        if (pAttr) {
            LOG_F(0, "dwAttrType=(%d), fDataType= (%d)", pAttr->dwAttrType, pAttr->fDataType);
            
            RADIUS_ATTRIBUTE* pNewAttr = new RADIUS_ATTRIBUTE();
            pNewAttr->cbDataLength = pAttr->cbDataLength;
            pNewAttr->dwAttrType = pAttr->dwAttrType;
            pNewAttr->fDataType = pAttr->fDataType;

            if (pAttr->fDataType == rdtUnknown || pAttr->fDataType == rdtString || pAttr->fDataType == rdtIpv6Address) {
                pNewAttr->lpValue = (CONST BYTE*) RadiusAlloc(pAttr->cbDataLength);
                memcpy((void*)pNewAttr->lpValue, pAttr->lpValue, pAttr->cbDataLength);
            }
            else {
                pNewAttr->dwValue = pAttr->dwValue;
            }
            vecAttrs.push_back(pNewAttr);            
        }


    }

    return vecAttrs;
}

int ReplaceAttrs(PRADIUS_ATTRIBUTE_ARRAY pExisting, vector<RADIUS_ATTRIBUTE*> cached) {
    //due to memory allocation and other reasons, we may not be able to do assign the pointer.
    // pExisting = pCached;
    // remove the existing items;
    DWORD size = pExisting->GetSize(pExisting);
    while(size > 0) {
        size--;
        const RADIUS_ATTRIBUTE* pAttr = pExisting->AttributeAt(pExisting, size);
        if (pAttr->dwAttrType != ratState) {
            pExisting->RemoveAt(pExisting, size);
        }
    }
    

    size = pExisting->GetSize(pExisting);
    LOG_F(0, "After removal =(%d) ", size);
    for (int i = 0; i < size; i++) {
        const RADIUS_ATTRIBUTE* pAttr = pExisting->AttributeAt(pExisting, i);
        if (pAttr) {
            LOG_F(0, "dwAttrType=(%d), fDataType= (%d)", pAttr->dwAttrType, pAttr->fDataType);
        }
    }

    for (int i = 0; i < cached.size(); i++) {
        const RADIUS_ATTRIBUTE* pAttr = cached[i];
        if (pAttr->dwAttrType == ratCode)
            continue;
        if (pAttr->dwAttrType == ratIdentifier)
            continue;
        if (pAttr->dwAttrType == ratAuthenticator)
            continue;
        if (pAttr->dwAttrType == ratSrcIPAddress)
            continue;
        if (pAttr->dwAttrType == ratSrcPort)
            continue;
        if (pAttr->dwAttrType == ratUniqueId)
            continue;

        pExisting->Add(pExisting, pAttr);
    }


    return 0;
}

std::string hexStr(const BYTE *data, int len)
{
     std::stringstream ss;
     ss << std::hex;

     for( int i(0) ; i < len; ++i )
         ss << std::setw(2) << std::setfill('0') << (int)data[i];

     return ss.str();
}

int counter = 0;

/*
* extern "C"
DWORD
WINAPI
*/

STDAPI_(DWORD) RadiusExtensionProcess2(
   PRADIUS_EXTENSION_CONTROL_BLOCK pECB
   )
{
   PRADIUS_ATTRIBUTE_ARRAY pInAttrs;
   const RADIUS_ATTRIBUTE* pAttr;

   LOG_F(0, "repPoint=(%d) rcRequestType=(%d) rcResponseType=(%d)",
       pECB->repPoint, pECB->rcRequestType, pECB->rcResponseType);

   /* We only process authentication. */
   if (pECB->repPoint != repAuthentication)
   {
      return NO_ERROR;
   }

   /* We only process Access-Requests. */
   if (pECB->rcRequestType != rcAccessRequest)
   {
      return NO_ERROR;
   }

   /* Don't process if it's already been rejected. */
   if (pECB->rcResponseType == rcAccessReject)
   {
      return NO_ERROR;
   }

   /* Get the attributes from the Access-Request. */
   pInAttrs = pECB->GetRequest(pECB);

   /* Retrieve the state. */
   pAttr = RadiusFindFirstAttribute(pInAttrs, ratState);
   counter++;
   if ((counter&1) == 0)
   {
        DWORD size = pInAttrs->GetSize(pInAttrs);
        for (DWORD i = 0; i < size; i++) {
            pAttr = pInAttrs->AttributeAt(pInAttrs, i);
            if (pAttr->dwAttrType == ratState) {
                LOG_F(0, "Found state, remove it");
                pInAttrs->RemoveAt(pInAttrs, i);
                break;
            }
        }
        size = pInAttrs->GetSize(pInAttrs);
        for (DWORD i = 0; i < size; i++) {
            pAttr = pInAttrs->AttributeAt(pInAttrs, i);
            if (pAttr->dwAttrType == 80) {
                LOG_F(0, "Found Message-Authenticator, remove it");
                pInAttrs->RemoveAt(pInAttrs, i);
                break;
            }
        }


       return NO_ERROR;
        string state = hexStr(pAttr->lpValue, pAttr->cbDataLength);
        LOG_F(0, "state in the Request = (%s)", state.c_str());
        pAttr = RadiusFindFirstAttribute(pInAttrs, ratUserPassword);   //test on PAP, OTP is in ratUserPassword.

        if (pAttr)
        {
            char otpCode[256];    //big enough
            memset(otpCode, 0, 256);
            memcpy(otpCode, pAttr->lpValue, pAttr->cbDataLength);
            LOG_F(0, "OTP code entered = (%s)", otpCode);
            // test OTP matched
            if (memcmp(otpCode, "123456", 6) == 0)
            {
                auto search = cacheMap.find(state);
                if ( search != cacheMap.end()){
                    //replace the current one by the cache
                    vector<RADIUS_ATTRIBUTE*> pCached = search->second;
                    LOG_F(0, "Before replacement Size=(%d)", pInAttrs->GetSize(pInAttrs));
                    for (DWORD i = 0; i < pInAttrs->GetSize(pInAttrs); i++) {
                        pAttr = pInAttrs->AttributeAt(pInAttrs, i);
                        LOG_F(0, "dwAttrType=(%d), fDataType= (%d)", pAttr->dwAttrType, pAttr->fDataType);
                    }

                    ReplaceAttrs(pInAttrs, pCached);
                    //remove it from the map
                    cacheMap.erase(state);
                    LOG_F(0, "New Attr Size=(%d)",  pInAttrs->GetSize(pInAttrs));
                    // continue to NPS to do the normal authentication at AD DC
                    LOG_F(0, "Continue to NPS");
                }
                else
                {
                    //Not in the cache
                    LOG_F(0, "No cached AD Password or its variant");
                    DWORD nRet = pECB->SetResponseType(pECB, rcAccessReject);
                    pECB->rcResponseType = rcAccessReject;
                    return NO_ERROR;
                }
            }
            else
            {
                LOG_F(0, "Incorrect OTP code, Access Denied");
                DWORD nRet = pECB->SetResponseType(pECB, rcAccessReject);
                pECB->rcResponseType = rcAccessReject;
                return NO_ERROR;
            }
        }
        else {
            for (DWORD i = 0; i < pInAttrs->GetSize(pInAttrs); i++) {
                pAttr = pInAttrs->AttributeAt(pInAttrs, i);
                if (pAttr->dwAttrType == ratState) {
                    LOG_F(0, "Found state, remove it");
                    pInAttrs->RemoveAt(pInAttrs, i);
                    break;
                }
            }

            LOG_F(0, "No ratUserPassword");
        }
   }
   else 
   {
    // Generally it is the first request packet.  
    //On behalf of NPS, send back a response of rcAccessChallenge
        DWORD nRet = pECB->SetResponseType(pECB, rcAccessChallenge);     
        pECB->rcResponseType = rcAccessChallenge;   // is this redundant?
        //this is for response
        PRADIUS_ATTRIBUTE_ARRAY pResAttrs = pECB->GetResponse(pECB, rcAccessChallenge);

        RADIUS_ATTRIBUTE raPromptMsg;

        /* Fill in the RADIUS_ATTRIBUTE struct. */
        char ReplyMsg[] = "Please Enter OTP Code";
        DWORD cbDataLength = strlen(ReplyMsg);
        raPromptMsg.fDataType = rdtString;
        raPromptMsg.cbDataLength = cbDataLength;
        raPromptMsg.lpValue = (const BYTE*)ReplyMsg;

        /* Add the ratReplyMessage */
        raPromptMsg.dwAttrType = ratReplyMessage;
        pResAttrs->Add(pResAttrs, &raPromptMsg);

        //Add Random State Information
        RADIUS_ATTRIBUTE raStateValue;
        raStateValue.dwAttrType = ratState;
        raStateValue.fDataType = rdtString;
        raStateValue.cbDataLength = 16;
        raStateValue.lpValue = (CONST BYTE*)RadiusAlloc(16);
        memcpy((void*)raStateValue.lpValue, "1234567890123456", 16);
        pResAttrs->Add(pResAttrs, &raStateValue);

    
        // also cache the original request attributes
        string state = hexStr(raStateValue.lpValue, raStateValue.cbDataLength);
        LOG_F(0, "state in the Challenge response along with ratReplyMessage = (%s)", state.c_str());

        vector<RADIUS_ATTRIBUTE*> vecAttrs = CacheAttrs(pInAttrs);
        cacheMap.insert(std::make_pair(state, vecAttrs));
   }


   return NO_ERROR;

}

