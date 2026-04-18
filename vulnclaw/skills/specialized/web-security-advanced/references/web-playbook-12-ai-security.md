# AI安全
English: AI Security
- Entry Count: 4
- Use this file to shortlist relevant payloads, then open the linked source markdown for the full workflow and commands.
## LLM提示注入攻击
- ID: ai-prompt-injection
- Difficulty: beginner
- Subcategory: 提示注入
- Tags: AI, LLM, Prompt Injection, ChatGPT, 提示注入
- Original Extracted Source: original extracted web-security-wiki source/ai-prompt-injection.md
Description:
通过精心构造的用户输入覆盖或绕过LLM(大语言模型)的系统提示(System Prompt)，使AI执行非预期的操作。包括直接注入(DPI)和间接注入(IPI)，可导致系统提示泄露、安全护栏绕过、数据泄露和未授权操作。
Prerequisites:
- 目标应用集成了LLM
- 可与LLM交互输入文本
Execution Outline:
1. 1. 系统提示泄露
2. 2. 安全护栏绕过
3. 3. 间接提示注入(IPI)
4. 4. 利用AI工具调用(Function Calling)
## AI模型窃取与推理攻击
- ID: ai-model-extraction
- Difficulty: advanced
- Subcategory: 模型攻击
- Tags: AI, 模型窃取, Model Extraction, 成员推断, API滥用
- Original Extracted Source: original extracted web-security-wiki source/ai-model-extraction.md
Description:
通过大量精心构造的查询对AI模型进行黑盒攻击，窃取模型参数(Model Extraction)、推断训练数据(Membership Inference)或发现模型决策边界。攻击者可以此构建功能等价的替代模型或提取隐私数据。
Prerequisites:
- 目标提供AI推理API
- API返回概率/置信度分数
Execution Outline:
1. 1. API探测与能力分析
2. 2. 模型窃取(Model Extraction)
3. 3. 成员推断攻击(MIA)
4. 4. 训练数据提取
## 对抗样本攻击
- ID: ai-adversarial
- Difficulty: expert
- Subcategory: 对抗攻击
- Tags: AI, 对抗样本, Adversarial, FGSM, Evasion
- Original Extracted Source: original extracted web-security-wiki source/ai-adversarial.md
Description:
通过向输入数据中添加人类不可感知的微小扰动，使AI模型产生错误的预测结果。对抗样本攻击可应用于图像分类、文本分析、语音识别等多种AI模型，威胁自动驾驶、安全检测和内容审核系统。
Prerequisites:
- 目标使用AI进行自动化决策
- 可控制输入数据
Execution Outline:
1. 1. 白盒攻击——FGSM
2. 2. 黑盒攻击——基于查询
3. 3. 文本对抗攻击
4. 4. 物理世界对抗攻击
## RAG投毒与知识库注入
- ID: ai-rag-poisoning
- Difficulty: intermediate
- Subcategory: RAG攻击
- Tags: AI, RAG, 知识库, 向量数据库, 数据投毒
- Original Extracted Source: original extracted web-security-wiki source/ai-rag-poisoning.md
Description:
针对使用RAG(Retrieval-Augmented Generation)架构的AI应用，通过投毒知识库中的文档来影响AI的回答。攻击者可在向量数据库中注入包含恶意指令的文档，当用户查询触发检索时，恶意文档被注入到AI上下文中执行间接提示注入。
Prerequisites:
- 目标使用RAG架构
- 可向知识库提交文档
- 了解RAG检索机制
Execution Outline:
1. 1. RAG架构识别与分析
2. 2. 知识库投毒——注入恶意文档
3. 3. 触发投毒文档检索
4. 4. 向量数据库直接攻击

