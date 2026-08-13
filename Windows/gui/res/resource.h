#ifndef RESOURCE_H
#define RESOURCE_H

// App version - single source of truth
// Feeds the About dialog (via loc.h APP_VERSION) and the VS_VERSION_INFO resource
// (exe Properties → Details). Also mirror the numeric form in res\app.manifest's
// <assemblyIdentity version="..."> when bumping.
#define PB_VER_MAJOR 4
#define PB_VER_MINOR 0
#define PB_VER_PATCH 11
#define PB_VER_BUILD 0
#define PB_VER_STR   "4.0.13-Beta"     // narrow, for the .rc VERSIONINFO strings
#define PB_VER_STRW  L"4.0.13-Beta"    // wide, for the C/About UI

#define IDI_APPICON                 101

// Menu
#define IDR_MAINMENU                200
#define IDM_PROXY_SETTINGS          201
#define IDM_PROXY_RULES             202
#define IDM_SET_LOCALHOST           210
#define IDM_SET_TRAFFICLOG          211
#define IDM_SET_CLOSETOTRAY         212
#define IDM_SET_STARTUP             215
#define IDM_SET_AUTOCLEAR           216
#define IDM_LOG_FILTERS             217
#define IDM_PROFILE_RENAME          244

// Log Filters (list) dialog
#define IDD_FILTERS                600
#define IDC_FL_LIST                601
#define IDC_FL_ADD                 602
#define IDC_FL_EDIT                603
#define IDC_FL_REMOVE              604
#define IDC_FL_DESC                605

// Log Filter (edit) sub-dialog
#define IDD_FILTER                 620
#define IDC_FE_MODE                621
#define IDC_FE_PROC                622
#define IDC_FE_IP                  623
#define IDC_FE_PORT                624
#define IDC_FE_PROTO               625
#define IDC_FE_ACTION              626
#define IDC_FE_L_MODE              630
#define IDC_FE_L_PROC              631
#define IDC_FE_L_IP                632
#define IDC_FE_L_PORT              633
#define IDC_FE_L_PROTO             634
#define IDC_FE_L_ACTION            635
#define IDM_HELP_ABOUT              220
#define IDM_HELP_DOCS               221
#define IDM_HELP_UPDATE             222
#define IDM_TRAY_SHOW               230
#define IDM_TRAY_EXIT               231
#define IDM_PROFILE_NEW             240
#define IDM_PROFILE_DELETE          241
#define IDM_PROFILE_IMPORT          242
#define IDM_PROFILE_EXPORT          243
#define IDM_LANG_EN                 250
#define IDM_LANG_ZH                 251
#define IDM_PROFILE_SWITCH_BASE     2000   // switch items: base + index

// Proxy Servers (list) dialog
#define IDD_SERVERS                300
#define IDC_SV_LIST                301
#define IDC_SV_ADD                 302
#define IDC_SV_EDIT                303
#define IDC_SV_REMOVE              304
#define IDC_SV_CHECK               305

// Proxy Server (edit) sub-dialog
#define IDD_SERVER                 320
#define IDC_SE_ADDR                321
#define IDC_SE_PORT                322
#define IDC_SE_PROTO               323
#define IDC_SE_AUTH                324   // "Enable" authentication checkbox
#define IDC_SE_USER                325
#define IDC_SE_PASS                326
#define IDC_SE_L_ADDR              330
#define IDC_SE_L_PORT              331
#define IDC_SE_L_PROTO             332
#define IDC_SE_L_USER              333
#define IDC_SE_L_PASS              334
#define IDC_SE_G_SERVER            335   // "Server" group box
#define IDC_SE_G_AUTH              336   // "Authentication" group box
#define IDC_SE_NAME                327   // friendly name edit
#define IDC_SE_L_NAME              337   // "Name:" label
#define IDC_SE_SENDDOMAIN          328   // "let proxy resolve DNS" checkbox

// Proxy Checker dialog
#define IDD_CHECKER                340
#define IDC_CK_LOG                 341
#define IDC_CK_RETEST              342
#define IDC_CK_HOST                343
#define IDC_CK_PORT                344
#define IDC_CK_L_HOST              345
#define IDC_CK_L_PORT              346

// Proxification Rules (list) dialog
#define IDD_RULES                  400
#define IDC_RL_LIST                401
#define IDC_RL_ADD                 402
#define IDC_RL_CLONE               403
#define IDC_RL_EDIT                404
#define IDC_RL_REMOVE              405
#define IDC_RL_UP                  406
#define IDC_RL_DOWN                407
#define IDC_RL_HINT                408

// Proxification Rule (edit) sub-dialog
#define IDD_RULE                   420
#define IDC_RE_ENABLED             421
#define IDC_RE_APPS                422
#define IDC_RE_HOSTS               423
#define IDC_RE_PORTS               424
#define IDC_RE_DOMAINS             425
#define IDC_RE_PROTO               426
#define IDC_RE_ACTION              427
#define IDC_RE_L_APPS              430
#define IDC_RE_L_HOSTS             431
#define IDC_RE_L_PORTS             432
#define IDC_RE_L_DOMAINS           433
#define IDC_RE_L_PROTO             434
#define IDC_RE_L_ACTION            435
#define IDC_RE_BROWSE              436
#define IDC_RE_EX_APPS             437
#define IDC_RE_EX_HOSTS            438
#define IDC_RE_EX_PORTS            439
#define IDC_RE_EX_DOMAINS          440
#define IDC_RE_UDPNOTE             441
#define IDC_RE_NAME                442   // friendly name edit
#define IDC_RE_L_NAME              443   // "Name:" label

// Name-input dialog (new profile)
#define IDD_NAME                   500
#define IDC_NAME_EDIT              501
#define IDC_NAME_PROMPT            502

// Update notification dialog
#define IDD_UPDATE                 720
#define IDC_UP_TEXT                721
#define IDC_UP_VERS                722
#define IDC_UP_DATE                723
#define IDC_UP_NOTES               724
#define IDC_UP_PROGRESS            725
#define IDC_UP_STATUS              726
#define IDC_UP_NOW                 727
#define IDC_UP_DONTASK             728

// About dialog
#define IDD_ABOUT                  700
#define IDC_AB_TITLE               701
#define IDC_AB_VER                 702
#define IDC_AB_DESC                703
#define IDC_AB_AUTHOR              704
#define IDC_AB_WEB                 705
#define IDC_AB_GITHUB              706
#define IDC_AB_LICENSE             707

#endif // RESOURCE_H
