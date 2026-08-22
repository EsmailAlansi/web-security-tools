#!/bin/bash
# =====================================================================
# Param_Scanner – أداة متقدمة لاكتشاف وفحص الباراميترات في الروابط
# الإصدار: 1.0
# الغرض: كشف الباراميترات المخفية في صفحات الويب وتحديد الثغرات فيها
# التقنيات: sqlmap (crawl/forms) + curl + grep + regex
# المتطلبات: sqlmap, curl, python3 (اختياري)
# =====================================================================

# الألوان
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[1;35m'
NC='\033[0m'

# الإعدادات الافتراضية
TARGET=""
COOKIE=""
DEPTH=2
THREADS=5
OUTPUT_DIR="param_scan_results"

# الشعار
show_banner() {
    echo -e "${PURPLE}"
    echo "  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗"
    echo "  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║"
    echo "  ██████╔╝███████║██████╔╝███████║██╔████╔██║"
    echo "  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║"
    echo "  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║"
    echo "  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝"
    echo -e "${NC}"
    echo -e "${CYAN}  محرك كشف الباراميترات – فحص ذكي وسريع للروابط${NC}"
    echo -e "${YELLOW}  للاستخدام التعليمي فقط على أنظمة تملك إذن الاختبار${NC}"
    echo ""
}

# دالة التحقق من التبعيات
check_deps() {
    for tool in sqlmap curl grep; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[-] الأداة $tool غير مثبتة!${NC}"
            exit 1
        fi
    done
}

# دالة إعداد الهدف
set_target() {
    echo -e "${BLUE}[>] أدخل الرابط المستهدف (URL):${NC}"
    read -p "> " TARGET
    if [ -z "$TARGET" ]; then
        echo -e "${RED}[-] الرابط فارغ!${NC}"
        return 1
    fi
    # التأكد من وجود http/https
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        echo -e "${YELLOW}[!] لم يتم إضافة البروتوكول، سيتم إضافة http:// تلقائياً${NC}"
        TARGET="http://$TARGET"
    fi
    echo -e "${GREEN}[✓] الهدف: $TARGET${NC}"
    
    # سؤال عن الكوكيز
    read -p "هل تريد إضافة كوكيز (اختياري)؟ [y/N]: " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        read -p "أدخل الكوكي (مثال PHPSESSID=...): " COOKIE
        echo -e "${GREEN}[✓] تم إضافة الكوكي: $COOKIE${NC}"
    fi
    
    # سؤال عن عمق الفحص
    read -p "أدخل عمق الزحف (Crawl Depth) الافتراضي 2: " depth_ans
    if [[ "$depth_ans" =~ ^[0-9]+$ ]]; then
        DEPTH=$depth_ans
    fi
    echo -e "${GREEN}[✓] عمق الزحف: $DEPTH${NC}"
    
    # سؤال عن عدد الخيوط
    read -p "أدخل عدد الخيوط (Threads) الافتراضي 5: " thread_ans
    if [[ "$thread_ans" =~ ^[0-9]+$ ]]; then
        THREADS=$thread_ans
    fi
    echo -e "${GREEN}[✓] عدد الخيوط: $THREADS${NC}"
}

# دالة استخراج الباراميترات من صفحة باستخدام curl
extract_params_from_page() {
    local url="$1"
    echo -e "${CYAN}[*] تحليل الصفحة: $url${NC}"
    
    # جلب محتوى الصفحة
    local html
    if [ -n "$COOKIE" ]; then
        html=$(curl -s -L -b "$COOKIE" "$url" 2>/dev/null)
    else
        html=$(curl -s -L "$url" 2>/dev/null)
    fi
    
    # استخراج الروابط والباراميترات (GET)
    echo -e "${BLUE}  روابط GET الموجودة في الصفحة:${NC}"
    local get_links
    get_links=$(echo "$html" | grep -oP 'href=["'"'"'][^"'"'"']*\?[^"'"'"']*["'"'"']' | sed 's/href=["'"'"']//;s/["'"'"']$//' | sort -u)
    if [ -z "$get_links" ]; then
        echo -e "${YELLOW}    لا توجد روابط GET واضحة"
    else
        echo "$get_links" | while read -r link; do
            echo -e "${GREEN}    [+] $link${NC}"
        done
    fi
    
    # استخراج نماذج POST
    echo -e "${BLUE}  نماذج POST الموجودة في الصفحة:${NC}"
    local forms
    forms=$(echo "$html" | grep -oP '<form[^>]*>' | sed 's/<form//;s/>//' | tr ' ' '\n' | grep -E 'action|method' | sort -u)
    if [ -z "$forms" ]; then
        echo -e "${YELLOW}    لا توجد نماذج POST"
    else
        echo "$forms" | while read -r line; do
            echo -e "${GREEN}    [+] $line${NC}"
        done
    fi
    
    # استخراج أسماء الحقول (input names)
    echo -e "${BLUE}  حقول الإدخال الموجودة:${NC}"
    local input_names
    input_names=$(echo "$html" | grep -oP 'name=["'"'"'][^"'"'"']*["'"'"']' | sed 's/name=["'"'"']//;s/["'"'"']$//' | sort -u)
    if [ -z "$input_names" ]; then
        echo -e "${YELLOW}    لا توجد حقول إدخال"
    else
        echo "$input_names" | while read -r name; do
            echo -e "${GREEN}    [+] input name=$name${NC}"
        done
    fi
}

# دالة فحص شامل باستخدام sqlmap crawl
sqlmap_crawl_scan() {
    echo -e "${CYAN}[*] بدء فحص شامل بالزحف التلقائي (sqlmap --crawl)${NC}"
    local cmd="sqlmap -u \"$TARGET\" --crawl=$DEPTH --batch --level=3 --risk=2 --threads=$THREADS --forms --output-dir=\"$OUTPUT_DIR\""
    if [ -n "$COOKIE" ]; then
        cmd+=" --cookie=\"$COOKIE\""
    fi
    echo -e "${WHITE}$cmd${NC}"
    eval "$cmd"
    echo -e "${GREEN}[✓] تم الانتهاء من الفحص، النتائج في $OUTPUT_DIR${NC}"
}

# دالة فحص الباراميترات المكتشفة يدوياً (اختياري)
manual_param_scan() {
    if [ -z "$TARGET" ]; then
        echo -e "${RED}حدد الهدف أولاً!${NC}"
        return
    fi
    
    echo -e "${CYAN}[*] جلب الروابط من الصفحة وفحصها بواسطة sqlmap${NC}"
    local links_file="$OUTPUT_DIR/links.txt"
    mkdir -p "$OUTPUT_DIR"
    
    # استخراج كل الروابط من الصفحة
    if [ -n "$COOKIE" ]; then
        curl -s -L -b "$COOKIE" "$TARGET" | grep -oP 'href=["'"'"'][^"'"'"']*["'"'"']' | sed 's/href=["'"'"']//;s/["'"'"']$//' | grep '?' | sort -u > "$links_file"
    else
        curl -s -L "$TARGET" | grep -oP 'href=["'"'"'][^"'"'"']*["'"'"']' | sed 's/href=["'"'"']//;s/["'"'"']$//' | grep '?' | sort -u > "$links_file"
    fi
    
    if [ ! -s "$links_file" ]; then
        echo -e "${YELLOW}لا توجد روابط تحتوي على باراميترات في هذه الصفحة${NC}"
        return
    fi
    
    echo -e "${BLUE}الروابط المكتشفة:${NC}"
    cat "$links_file"
    
    echo -e "${CYAN}[>] هل تريد فحص كل رابط بواسطة sqlmap؟ [y/N]:${NC}"
    read -p "> " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        while IFS= read -r link; do
            # تجاهل الروابط التي ليست من نفس النطاق (اختياري)
            echo -e "${CYAN}[*] فحص الرابط: $link${NC}"
            sqlmap -u "$link" --batch --level=2 --risk=1 --output-dir="$OUTPUT_DIR" --cookie="$COOKIE"
        done < "$links_file"
        echo -e "${GREEN}[✓] تم فحص جميع الروابط${NC}"
    fi
}

# دالة تحليل JSON لاستخراج البيانات (اختياري متقدم)
advanced_scan() {
    echo -e "${BLUE}[>] هذه الميزة تتطلب python3 مع مكتبات إضافية، تخطيها مؤقتاً${NC}"
    sleep 1
}

# القائمة الرئيسية
main_menu() {
    while true; do
        show_banner
        echo -e "${BLUE}=== القائمة الرئيسية ===${NC}"
        echo -e "  ${WHITE}[1]${NC} تعيين الهدف"
        echo -e "  ${WHITE}[2]${NC} استخراج الباراميترات من الصفحة (curl)"
        echo -e "  ${WHITE}[3]${NC} فحص شامل بالزحف التلقائي (sqlmap crawl)"
        echo -e "  ${WHITE}[4]${NC} فحص كل الروابط المكتشفة يدوياً"
        echo -e "  ${WHITE}[5]${NC} إعدادات متقدمة (عمق/خيوط)"
        echo -e "  ${WHITE}[6]${NC} حذف النتائج"
        echo -e "  ${WHITE}[0]${NC} خروج"
        echo
        read -p "اختر رقم: " choice

        case $choice in
            0) echo -e "${GREEN}وداعاً!${NC}"; exit 0 ;;
            1) set_target ;;
            2) 
                if [ -z "$TARGET" ]; then echo -e "${RED}حدد الهدف أولاً!${NC}"; sleep 2; else extract_params_from_page "$TARGET"; read -p "اضغط Enter للمتابعة..." ; fi
                ;;
            3) sqlmap_crawl_scan ;;
            4) manual_param_scan ;;
            5)
                read -p "أدخل عمق الزحف الجديد: " DEPTH
                read -p "أدخل عدد الخيوط الجديد: " THREADS
                echo -e "${GREEN}[✓] تم التحديث: depth=$DEPTH, threads=$THREADS${NC}"
                sleep 1
                ;;
            6) 
                rm -rf "$OUTPUT_DIR"
                echo -e "${GREEN}[✓] تم حذف النتائج${NC}"
                sleep 1
                ;;
            *) echo -e "${RED}اختيار غير صحيح!${NC}"; sleep 1 ;;
        esac
    done
}

# نقطة البداية
check_deps
mkdir -p "$OUTPUT_DIR"
main_menu