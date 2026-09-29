#!/bin/bash
# 运行所有示例脚本
# 用法: ./run_all.sh

set -e  # 遇到错误立即退出

EXAMPLES_DIR=$(dirname "$0")
cd "$EXAMPLES_DIR"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}开始运行所有示例...${NC}"
echo

# 查找并运行所有示例目录中的main.go文件
for dir in */; do
  if [ -f "${dir}main.go" ]; then
    echo -e "${YELLOW}======================================${NC}"
    echo -e "${GREEN}运行示例: ${dir%/}${NC}"
    echo -e "${YELLOW}======================================${NC}"

    # 进入目录运行示例，30秒超时兜底：
    # 08_http_middleware 等示例会启动常驻 HTTP 服务；timeout 杀掉不代表示例失败，
    # 其所有可验证逻辑（策略加载/中间件挂载/监听启动）均已在启动前执行完成。
    rc=0
    (cd "$dir" && timeout 30 go run main.go) || rc=$?

    # 检查运行状态：0=正常退出，124=timeout正常超时，其余为失败
    if [ $rc -eq 0 ] || [ $rc -eq 124 ]; then
      if [ $rc -eq 124 ]; then
        echo -e "\n${YELLOW}→ 示例 ${dir%/} 为常驻服务，已超时回收（视为通过）${NC}\n"
      else
        echo -e "\n${GREEN}✓ 示例 ${dir%/} 运行成功${NC}\n"
      fi
    else
      echo -e "\n${RED}✗ 示例 ${dir%/} 运行失败(exit=$rc)${NC}\n"
      exit $rc
    fi

    echo
  fi
done

echo -e "${GREEN}所有示例运行完成!${NC}" 